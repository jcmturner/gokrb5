// +build disabled

package crypto

import (
	"crypto/aes"
	"crypto/sha256"
	"github.com/jcmturner/gokrb5/crypto/engine"
	"github.com/jcmturner/gokrb5/iana/chksumtype"
	"github.com/jcmturner/gokrb5/iana/etypeID"
	"hash"
)

// RFC https://tools.ietf.org/html/rfc8009

type Aes128CtsHmacSha256128 struct {
}

func (e Aes128CtsHmacSha256128) GetETypeID() int {
	return etypeID.AES128_CTS_HMAC_SHA256_128
}

func (e Aes128CtsHmacSha256128) GetHashID() int {
	return chksumtype.HMAC_SHA256_128_AES128
}

func (e Aes128CtsHmacSha256128) GetKeyByteSize() int {
	return 128 / 8
}

func (e Aes128CtsHmacSha256128) GetKeySeedBitLength() int {
	return e.GetKeyByteSize() * 8
}

func (e Aes128CtsHmacSha256128) GetHash() func() hash.Hash {
	return sha256.New
}

func (e Aes128CtsHmacSha256128) GetMessageBlockByteSize() int {
	return 1
}

func (e Aes128CtsHmacSha256128) GetDefaultStringToKeyParams() string {
	return "00008000"
}

func (e Aes128CtsHmacSha256128) GetConfounderByteSize() int {
	return aes.BlockSize
}

func (e Aes128CtsHmacSha256128) GetHMACBitLength() int {
	return 128
}

func (e Aes128CtsHmacSha256128) GetCypherBlockBitLength() int {
	return aes.BlockSize * 8
}

func (e Aes128CtsHmacSha256128) StringToKey(secret string, salt string, s2kparams string) ([]byte, error) {
	saltp := e.getSaltP(salt)
	return stringToKeySHA2(secret, saltp, s2kparams, e)
}

func (e Aes128CtsHmacSha256128) getSaltP(salt string) string {
	b := []byte("aes128-cts-hmac-sha256-128")
	b = append(b, byte(uint8(0)))
	b = append(b, []byte(salt)...)
	return string(b)
}

func (e Aes128CtsHmacSha256128) RandomToKey(b []byte) []byte {
	return randomToKey(b)
}

func (e Aes128CtsHmacSha256128) EncryptData(key, message []byte) ([]byte, []byte, error) {
	ivz := make([]byte, aes.BlockSize)
	return encryptCTS(key, ivz, message, e)
}

func (e Aes128CtsHmacSha256128) DecryptData(key, ciphertext []byte) ([]byte, error) {
	return decryptCTS(key, ciphertext, e)
}

func (e Aes128CtsHmacSha256128) DeriveKey(protocolKey, usage []byte) ([]byte, error) {
	return deriveKeyKDF_HMAC_SHA2(protocolKey, usage, e), nil
}

func (e Aes128CtsHmacSha256128) DeriveRandom(protocolKey, usage []byte) ([]byte, error) {
	return deriveRandomKDF_HMAC_SHA2(protocolKey, usage, e)
}

func (e Aes128CtsHmacSha256128) VerifyIntegrity(protocolKey, ct, pt []byte, usage uint32) bool {
	return engine.VerifyIntegrity(protocolKey, ct, pt, usage, e)
}
