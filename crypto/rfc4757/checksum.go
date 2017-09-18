package rfc4757

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"io"
)

func Checksum(key []byte, T uint32, data []byte) ([]byte, error) {
	// Create hashing key
	s := append([]byte(`signaturekey`), byte(0x00)) //includes zero octet at end
	mac := hmac.New(md5.New, key)
	mac.Write(s)
	Ksign := mac.Sum(nil)

	// Format data
	tb := MessageTypeBytes(T)
	p := append(tb, data...)
	h := md5.New()
	rb := bytes.NewReader(p)
	_, err := io.Copy(h, rb)
	if err != nil {
		return []byte{}, err
	}
	tmp := h.Sum(nil)

	// Generate HMAC
	mac = hmac.New(md5.New, Ksign)
	mac.Write(tmp)
	return mac.Sum(nil), nil
}

func HMAC(key []byte, data []byte) []byte {
	mac := hmac.New(md5.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
