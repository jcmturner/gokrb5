package crypto

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"errors"
	"fmt"
	"hash"
)

//RFC: 3961 Section 6.3

/*
                 des3-cbc-hmac-sha1-kd, hmac-sha1-des3-kd
              ------------------------------------------------
              protocol key format     24 bytes, parity in low
                                      bit of each

              key-generation seed     21 bytes
              length

              hash function           SHA-1

              HMAC output size        160 bits

              message block size      8 bytes

              default string-to-key   empty string
              params

              encryption and          triple-DES encrypt and
              decryption functions    decrypt, in outer-CBC
                                      mode (cipher block size
                                      8 octets)

              key generation functions:

              random-to-key           DES3random-to-key (see
                                      below)

              string-to-key           DES3string-to-key (see
                                      below)

   The des3-cbc-hmac-sha1-kd encryption type is assigned the value
   sixteen (16).  The hmac-sha1-des3-kd checksum algorithm is assigned a
   checksum type number of twelve (12)*/

type Des3CbcSha1Kd struct {
}

func (e Des3CbcSha1Kd) GetETypeID() int {
	return 16
}

func (e Des3CbcSha1Kd) GetKeyByteSize() int {
	return 24
}

func (e Des3CbcSha1Kd) GetKeySeedBitLength() int {
	return 21 * 8
}

func (e Des3CbcSha1Kd) GetHash() hash.Hash {
	return sha1.New()
}

func (e Des3CbcSha1Kd) GetMessageBlockByteSize() int {
	//For traditional CBC mode with padding, it would be the underlying cipher's block size
	return des.BlockSize
}

func (e Des3CbcSha1Kd) GetDefaultStringToKeyParams() string {
	var s string
	return s
}

func (e Des3CbcSha1Kd) GetConfounderByteSize() int {
	return des.BlockSize
}

func (e Des3CbcSha1Kd) GetHMACBitLength() int {
	return e.GetHash().Size()
}

func (e Des3CbcSha1Kd) GetCypherBlockBitLength() int {
	return des.BlockSize * 8
}

func (e Des3CbcSha1Kd) StringToKey(secret string, salt string, s2kparams string) (protocolKey []byte, err error) {
	//TODO
	return
}

func (e Des3CbcSha1Kd) RandomToKey(b []byte) (protocolKey []byte) {
	//TODO
	return
}

func (e Des3CbcSha1Kd) DeriveRandom(protocolKey, usage []byte) ([]byte, error) {
	r, err := deriveRandom(protocolKey, usage, e.GetCypherBlockBitLength(), e.GetKeySeedBitLength(), e)
	return r, err
}

func (e Des3CbcSha1Kd) DeriveKey(protocolKey, usage []byte) ([]byte, error) {
	r, err := e.DeriveRandom(protocolKey, usage)
	if err != nil {
		return nil, err
	}
	return e.RandomToKey(r), nil
}

func (e Des3CbcSha1Kd) Encrypt(key, message []byte) ([]byte, []byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return nil, nil, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeySeedBitLength(), len(key))

	}
	if len(message)%e.GetMessageBlockByteSize() != 0 {
		message, _ = pkcs7Pad(message, e.GetMessageBlockByteSize())
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("Error creating cipher: %v", err)

	}

	//RFC 3961: initial cipher state      All bits zero
	iv := make([]byte, e.GetConfounderByteSize())
	//_, err = rand.Read(iv) //Not needed as all bits need to be zero

	ct := make([]byte, len(message))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, message)
	return ct[:e.GetConfounderByteSize()], ct, nil
}

func (e Des3CbcSha1Kd) Decrypt(key, ciphertext []byte) (message []byte, err error) {
	if len(key) != e.GetKeySeedBitLength() {
		err = fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeySeedBitLength(), len(key))
		return
	}

	if len(ciphertext) < des.BlockSize || len(ciphertext)%des.BlockSize != 0 {
		err = errors.New("Ciphertext is not a multiple of the block size.")
		return
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		err = fmt.Errorf("Error creating cipher: %v", err)
		return
	}

	iv := ciphertext[:e.GetConfounderByteSize()]
	ciphertext = ciphertext[e.GetConfounderByteSize():]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(message, ciphertext)
	m, er := pkcs7Unpad(message, e.GetMessageBlockByteSize())
	if er == nil {
		message = m
	}
	return
}

func (e Des3CbcSha1Kd) VerifyIntegrity(protocolKey, ct, pt []byte, usage uint32) bool {
	return VerifyIntegrity(protocolKey, ct, pt, usage, e)
}
