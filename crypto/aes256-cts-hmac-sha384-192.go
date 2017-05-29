package crypto

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha512"
	"github.com/jcmturner/gokrb5/crypto/common"
	"github.com/jcmturner/gokrb5/crypto/rfc8009"
	"github.com/jcmturner/gokrb5/iana/chksumtype"
	"github.com/jcmturner/gokrb5/iana/etypeID"
	"hash"
)

// RFC https://tools.ietf.org/html/rfc8009

type Aes256CtsHmacSha384192 struct {
}

func (e Aes256CtsHmacSha384192) GetETypeID() int {
	return etypeID.AES256_CTS_HMAC_SHA384_192
}

func (e Aes256CtsHmacSha384192) GetHashID() int {
	return chksumtype.HMAC_SHA384_192_AES256
}

func (e Aes256CtsHmacSha384192) GetKeyByteSize() int {
	return 192 / 8
}

func (e Aes256CtsHmacSha384192) GetKeySeedBitLength() int {
	return e.GetKeyByteSize() * 8
}

func (e Aes256CtsHmacSha384192) GetHashFunc() func() hash.Hash {
	return sha512.New384
}

func (e Aes256CtsHmacSha384192) GetMessageBlockByteSize() int {
	return 1
}

func (e Aes256CtsHmacSha384192) GetDefaultStringToKeyParams() string {
	return "00008000"
}

func (e Aes256CtsHmacSha384192) GetConfounderByteSize() int {
	return aes.BlockSize
}

func (e Aes256CtsHmacSha384192) GetHMACBitLength() int {
	return 192
}

func (e Aes256CtsHmacSha384192) GetCypherBlockBitLength() int {
	return aes.BlockSize * 8
}

func (e Aes256CtsHmacSha384192) StringToKey(secret string, salt string, s2kparams string) ([]byte, error) {
	saltp := rfc8009.GetSaltP(salt, "aes256-cts-hmac-sha384-192")
	return rfc8009.StringToKey(secret, saltp, s2kparams, e)
}

func (e Aes256CtsHmacSha384192) RandomToKey(b []byte) []byte {
	return rfc8009.RandomToKey(b)
}

func (e Aes256CtsHmacSha384192) EncryptData(key, data []byte) ([]byte, []byte, error) {
	return rfc8009.EncryptData(key, data, e)
}

func (e Aes256CtsHmacSha384192) EncryptMessage(key, message []byte, usage uint32) ([]byte, []byte, error) {
	return rfc8009.EncryptMessage(key, message, usage, e)
}

func (e Aes256CtsHmacSha384192) DecryptData(key, data []byte) ([]byte, error) {
	return rfc8009.DecryptData(key, data, e)
}

func (e Aes256CtsHmacSha384192) DecryptMessage(key, ciphertext []byte, usage uint32) ([]byte, error) {
	return rfc8009.DecryptMessage(key, ciphertext, usage, e)
}

func (e Aes256CtsHmacSha384192) DeriveKey(protocolKey, usage []byte) ([]byte, error) {
	return rfc8009.DeriveKey(protocolKey, usage, e), nil
}

func (e Aes256CtsHmacSha384192) DeriveRandom(protocolKey, usage []byte) ([]byte, error) {
	return rfc8009.DeriveRandom(protocolKey, usage, e)
}

// The HMAC is calculated over the cipher state concatenated with the
// AES output, instead of being calculated over the confounder and
// plaintext.  This allows the message receiver to verify the
// integrity of the message before decrypting the message.
// Therefore the pt value to this interface method is not use. Pass any []byte.
func (e Aes256CtsHmacSha384192) VerifyIntegrity(protocolKey, ct, pt []byte, usage uint32) bool {
	// We don't need ib just there for the interface
	return rfc8009.VerifyIntegrity(protocolKey, ct, usage, e)
}

func (e Aes256CtsHmacSha384192) GetChecksumHash(protocolKey, data []byte, usage uint32) ([]byte, error) {
	return common.GetHash(data, protocolKey, common.GetUsageKc(usage), e)
}

func (e Aes256CtsHmacSha384192) VerifyChecksum(protocolKey, data, chksum []byte, usage uint32) bool {
	c, err := e.GetChecksumHash(protocolKey, data, usage)
	if err != nil {
		return false
	}
	return hmac.Equal(chksum, c)
}
