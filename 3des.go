package hdm

import (
	"crypto/des"
	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/andreburgaud/crypt2go/padding"
	"log/slog"
)

func TripleDesEncrypt(data, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	mode := ecb.NewECBEncrypter(block)
	padder := padding.NewPkcs7Padding(block.BlockSize())
	data, err = padder.Pad(data)
	if err != nil {
		return nil, err
	}
	ct := make([]byte, len(data))
	mode.CryptBlocks(ct, data)
	return ct, nil
}

func TripleDesDecrypt(data, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		slog.Error(err.Error())
		return nil, err
	}
	mode := ecb.NewECBDecrypter(block)
	pt := make([]byte, len(data))
	mode.CryptBlocks(pt, data)
	padder := padding.NewPkcs7Padding(block.BlockSize())
	pt, err = padder.Unpad(pt)
	if err != nil {
		return nil, err
	}
	return pt, nil
}
