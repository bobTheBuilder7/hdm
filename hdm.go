package hdm

import (
	"bytes"
	"context"
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
)

var DefaultHeader = []byte{0xD5, 0x80, 0xD4, 0xB4, 0xD5, 0x84, 0x00, 0x07}

const adgCode = "86.23"

type Client struct {
	firstKey   []byte
	password   string
	sessionKey []byte
	addr       string
	skMutex    sync.RWMutex
	parserPool *fastjson.ParserPool
	seq        atomic.Int64
	bufferPool *sync.Pool
}

func New(password string, addr string) *Client {
	h := sha256.New()
	h.Write([]byte(password))
	firstKey := h.Sum(nil)[:24]

	return &Client{firstKey: firstKey, password: password, addr: addr, parserPool: new(fastjson.ParserPool), bufferPool: &sync.Pool{New: func() interface{} {
		return new(bytes.Buffer)
	}}}
}

func (h *Client) getBuffer() *bytes.Buffer {
	return h.bufferPool.Get().(*bytes.Buffer)
}

func (h *Client) putBuffer(buf *bytes.Buffer) {
	buf.Reset()
	h.bufferPool.Put(buf)
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
	request := h.getBuffer()
	defer h.putBuffer(request)

	payloadJson := h.getBuffer()
	defer h.putBuffer(payloadJson)

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
	request := h.getBuffer()
	defer h.putBuffer(request)

	payloadJson := h.getBuffer()
	defer h.putBuffer(payloadJson)

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
	request := h.getBuffer()
	defer h.putBuffer(request)

	payloadJson := h.getBuffer()
	defer h.putBuffer(payloadJson)

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

func CreateItem(productCode string, productName string, qty float64, price float64) *Item {
	return &Item{
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
	request := h.getBuffer()
	defer h.putBuffer(request)

	payloadJson := h.getBuffer()
	defer h.putBuffer(payloadJson)

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

func (h *Client) printPrepaymentReceipt(conn net.Conn, amount float64) ([]byte, error) {
	request := h.getBuffer()
	defer h.putBuffer(request)

	payloadJson := h.getBuffer()
	defer h.putBuffer(payloadJson)

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
	}{Seq: h.seq.Add(1), Items: nil, PaidAmount: 0, Mode: 3, Dep: 2, PartnerTin: nil, PartialAmount: 0, PaidAmountCard: amount, PrePaymentAmount: 0, UseExtPOS: false}

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

func (h *Client) printItemsReceipt(conn net.Conn, items []*Item, prepaymentAmount float64) ([]byte, error) {
	request := h.getBuffer()
	defer h.putBuffer(request)

	payloadJson := h.getBuffer()
	defer h.putBuffer(payloadJson)

	_, err := request.Write(DefaultHeader)
	if err != nil {
		return nil, err
	}

	_, err = request.Write([]byte{0x04, 0x00})
	if err != nil {
		return nil, err
	}

	var totalAmount float64
	for _, item := range items {
		totalAmount += item.Price * item.Qty
	}

	body := struct {
		Seq              int64   `json:"password"`
		Items            []*Item `json:"items"`
		PaidAmount       float64 `json:"paidAmount"`
		PaidAmountCard   float64 `json:"paidAmountCard"`
		PartialAmount    float64 `json:"partialAmount"`
		PrePaymentAmount float64 `json:"prePaymentAmount"`
		Mode             int     `json:"mode"`
		Dep              int     `json:"dep"`
		PartnerTin       *string `json:"partnerTin"`
		UseExtPOS        bool    `json:"useExtPOS"`
	}{Seq: h.seq.Add(1), Items: items, PaidAmount: 0, Mode: 2, Dep: 2, PartnerTin: nil, PartialAmount: 0, PaidAmountCard: totalAmount - prepaymentAmount, PrePaymentAmount: prepaymentAmount, UseExtPOS: false}

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

func (h *Client) PrintPrepaymentReceipt(ctx context.Context, amount float64) ([]byte, error) {
	d := &net.Dialer{}

	conn, err := d.DialContext(ctx, "tcp", h.addr)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.Close()
	}()

	err = h.operatorLogin(conn)
	if err != nil {
		return nil, err
	}

	return h.printPrepaymentReceipt(conn, amount)
}

func (h *Client) PrintItemsReceipt(ctx context.Context, items map[int64]*Item, prepaymentAmount float64) ([]byte, error) {
	d := &net.Dialer{}

	conn, err := d.DialContext(ctx, "tcp", h.addr)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.Close()
	}()

	err = h.operatorLogin(conn)
	if err != nil {
		return nil, err
	}

	var itemsArr []*Item
	for _, value := range items {
		itemsArr = append(itemsArr, value)
	}

	return h.printItemsReceipt(conn, itemsArr, prepaymentAmount)
}
