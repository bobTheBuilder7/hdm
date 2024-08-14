package hdm

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/valyala/fastjson"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var DefaultHeader = []byte{0xD5, 0x80, 0xD4, 0xB4, 0xD5, 0x84, 0x00, 0x07}

const adgCode = "0408"

type Client struct {
	firstKey   []byte
	password   string
	sessionKey []byte
	addr       string
	skMutex    sync.RWMutex
	parserPool *fastjson.ParserPool
	seq        atomic.Int64
}

func New(password string, addr string) *Client {
	h := sha256.New()
	h.Write([]byte(password))
	firstKey := h.Sum(nil)[:24]

	return &Client{firstKey: firstKey, password: password, addr: addr, parserPool: new(fastjson.ParserPool)}
}

func (h *Client) readResponse(conn net.Conn, password bool) ([]byte, error) {
	header := make([]byte, 30*1024)
	_, err := conn.Read(header)
	if err != nil {
		return nil, err
	}

	code := int16(binary.BigEndian.Uint16(header[5:7]))

	length := binary.BigEndian.Uint16(header[7:9])
	var resp []byte
	if length > 0 {
		if password {
			resp, err = TripleDesDecrypt(header[11:11+length], h.firstKey)
			if err != nil {
				return nil, err
			}
		} else {
			resp, err = TripleDesDecrypt(header[11:11+length], h.sessionKey)
			if err != nil {
				return nil, err
			}
		}
	}

	if code == 200 {
		return resp, nil
	} else {
		val, ok := codes[code]
		if ok {
			return nil, errors.New(val)
		}
		return nil, errors.New(fmt.Sprintf("Error code - %d", code))

	}
}

func (h *Client) getOperatorsAndDeps(conn net.Conn) ([]byte, error) {
	request := new(bytes.Buffer)
	payloadJson := new(bytes.Buffer)

	_, err := request.Write(DefaultHeader)
	if err != nil {
		return nil, err
	}

	_, err = request.Write([]byte{0x01, 0x00})
	if err != nil {
		return nil, err
	}

	body := struct {
		Password string `json:"password"`
	}{Password: h.password}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	encryptedBody, err := TripleDesEncrypt(bodyBytes, h.firstKey)
	if err != nil {
		return nil, err
	}

	payloadJson.Write(encryptedBody)

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(payloadJson.Len()))
	request.Write(length)

	_, err = request.Write(payloadJson.Bytes())
	if err != nil {
		return nil, err
	}

	_, err = conn.Write(request.Bytes())
	if err != nil {
		return nil, err
	}

	return h.readResponse(conn, true)
}

func (h *Client) operatorLogin(conn net.Conn) error {
	request := new(bytes.Buffer)
	payloadJson := new(bytes.Buffer)

	_, err := request.Write(DefaultHeader)
	if err != nil {
		return err
	}

	_, err = request.Write([]byte{0x02, 0x00})
	if err != nil {
		return err
	}

	body := struct {
		Password string `json:"password"`
		Cashier  int    `json:"cashier"`
		Pin      string `json:"pin"`
	}{Password: h.password, Cashier: 3, Pin: "3"}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return err
	}

	encryptedBody, err := TripleDesEncrypt(bodyBytes, h.firstKey)
	if err != nil {
		return err
	}

	payloadJson.Write(encryptedBody)

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(payloadJson.Len()))
	request.Write(length)

	_, err = request.Write(payloadJson.Bytes())
	if err != nil {
		return err
	}

	_, err = conn.Write(request.Bytes())
	if err != nil {
		return err
	}

	response, err := h.readResponse(conn, true)
	if err != nil {
		return err
	}
	parser := h.parserPool.Get()
	defer h.parserPool.Put(parser)

	parsedResp, err := parser.ParseBytes(response)
	if err != nil {
		return err
	}

	newKey := make([]byte, 24)
	_, err = base64.StdEncoding.Decode(newKey, parsedResp.GetStringBytes("key"))
	if err != nil {
		return err
	}

	h.sessionKey = newKey

	return nil
}

func (h *Client) printLastReceipt(conn net.Conn) error {
	request := new(bytes.Buffer)
	payloadJson := new(bytes.Buffer)

	_, err := request.Write(DefaultHeader)
	if err != nil {
		return err
	}

	_, err = request.Write([]byte{0x05, 0x00})
	if err != nil {
		return err
	}

	body := struct {
		Seq int64 `json:"seq"`
	}{Seq: h.seq.Add(1)}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return err
	}

	encryptedBody, err := TripleDesEncrypt(bodyBytes, h.sessionKey)
	if err != nil {
		return err
	}

	payloadJson.Write(encryptedBody)

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(payloadJson.Len()))
	request.Write(length)

	_, err = request.Write(payloadJson.Bytes())
	if err != nil {
		return err
	}

	_, err = conn.Write(request.Bytes())
	if err != nil {
		return err
	}

	_, err = h.readResponse(conn, false)
	if err != nil {
		return err
	}

	return nil
}

type Item struct {
	AdgCode     string  `json:"adgCode"`
	Dep         int     `json:"dep"`
	ProductCode string  `json:"productCode"`
	ProductName string  `json:"productName"`
	Qty         float64 `json:"qty"`
	Unit        string  `json:"unit"`
	Price       float64 `json:"price"`
}

func createItem(productCode string, productName string, qty float64, price float64) Item {
	return Item{
		AdgCode:     adgCode,
		Dep:         2,
		ProductCode: productCode,
		ProductName: productName,
		Qty:         qty,
		Unit:        "հատ",
		Price:       price,
	}
}

func (h *Client) printSimpleReceipt(conn net.Conn, amount float64) ([]byte, error) {
	request := new(bytes.Buffer)
	payloadJson := new(bytes.Buffer)

	_, err := request.Write(DefaultHeader)
	if err != nil {
		return nil, err
	}

	_, err = request.Write([]byte{0x04, 0x00})
	if err != nil {
		return nil, err
	}

	body := struct {
		Seq              int64   `json:"password"`
		Items            []Item  `json:"items"`
		PaidAmount       float64 `json:"paidAmount"`
		PaidAmountCard   float64 `json:"paidAmountCard"`
		PartialAmount    float64 `json:"partialAmount"`
		PrePaymentAmount float64 `json:"prePaymentAmount"`
		Mode             int     `json:"mode"`
		Dep              int     `json:"dep"`
		PartnerTin       *string `json:"partnerTin"`
		UseExtPOS        bool    `json:"useExtPOS"`
	}{Seq: h.seq.Add(1), Items: nil, PaidAmount: 0, Mode: 1, Dep: 2, PartnerTin: nil, PartialAmount: 0, PaidAmountCard: amount, PrePaymentAmount: 0, UseExtPOS: false}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	encryptedBody, err := TripleDesEncrypt(bodyBytes, h.sessionKey)
	if err != nil {
		return nil, err
	}

	payloadJson.Write(encryptedBody)

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(payloadJson.Len()))
	request.Write(length)

	_, err = request.Write(payloadJson.Bytes())
	if err != nil {
		return nil, err
	}

	_, err = conn.Write(request.Bytes())
	if err != nil {
		return nil, err
	}

	return h.readResponse(conn, false)
}

func (h *Client) PrintSimpleReceipt(amount float64) ([]byte, error) {
	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	err = conn.SetReadDeadline(time.Now().Add(3 * time.Minute))
	if err != nil {
		return nil, err
	}

	err = conn.SetWriteDeadline(time.Now().Add(3 * time.Minute))
	if err != nil {
		return nil, err
	}

	err = h.operatorLogin(conn)
	if err != nil {
		return nil, err
	}

	return h.printSimpleReceipt(conn, amount)
}
