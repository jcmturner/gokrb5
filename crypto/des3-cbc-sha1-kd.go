package crypto

import (
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"github.com/jcmturner/gokrb5/crypto/common"
	"github.com/jcmturner/gokrb5/crypto/rfc3961"
	"github.com/jcmturner/gokrb5/iana/chksumtype"
	"github.com/jcmturner/gokrb5/iana/etypeID"
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
	return etypeID.DES3_CBC_SHA1_KD
}

func (e Des3CbcSha1Kd) GetHashID() int {
	return chksumtype.HMAC_SHA1_DES3_KD
}

func (e Des3CbcSha1Kd) GetKeyByteSize() int {
	return 24
}

func (e Des3CbcSha1Kd) GetKeySeedBitLength() int {
	return 21 * 8
}

func (e Des3CbcSha1Kd) GetHashFunc() func() hash.Hash {
	return sha1.New
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
	return e.GetHashFunc()().Size() * 8
}

func (e Des3CbcSha1Kd) GetCypherBlockBitLength() int {
	return des.BlockSize * 8
}

func (e Des3CbcSha1Kd) StringToKey(secret string, salt string, s2kparams string) ([]byte, error) {
	if s2kparams != "" {
		return []byte{}, errors.New("s2kparams must be an empty string")
	}
	return rfc3961.DES3StringToKey(secret, salt, e)
}

func (e Des3CbcSha1Kd) RandomToKey(b []byte) []byte {
	return rfc3961.DES3RandomToKey(b)
}

func (e Des3CbcSha1Kd) DeriveRandom(protocolKey, usage []byte) ([]byte, error) {
	r, err := rfc3961.DeriveRandom(protocolKey, usage, e)
	return r, err
}

func (e Des3CbcSha1Kd) DeriveKey(protocolKey, usage []byte) ([]byte, error) {
	r, err := e.DeriveRandom(protocolKey, usage)
	if err != nil {
		return nil, err
	}
	return e.RandomToKey(r), nil
}

func (e Des3CbcSha1Kd) EncryptData(key, data []byte) ([]byte, []byte, error) {
	return rfc3961.DES3EncryptData(key, data, e)
}

func (e Des3CbcSha1Kd) EncryptMessage(key, message []byte, usage uint32) ([]byte, []byte, error) {
	return rfc3961.DES3EncryptMessage(key, message, usage, e)
}

func (e Des3CbcSha1Kd) DecryptData(key, data []byte) ([]byte, error) {
	return rfc3961.DES3DecryptData(key, data, e)
}

func (e Des3CbcSha1Kd) DecryptMessage(key, ciphertext []byte, usage uint32) (message []byte, err error) {
	return rfc3961.DES3DecryptMessage(key, ciphertext, usage, e)
}

func (e Des3CbcSha1Kd) VerifyIntegrity(protocolKey, ct, pt []byte, usage uint32) bool {
	return rfc3961.VerifyIntegrity(protocolKey, ct, pt, usage, e)
}

func (e Des3CbcSha1Kd) GetChecksumHash(protocolKey, data []byte, usage uint32) ([]byte, error) {
	return common.GetHash(data, protocolKey, common.GetUsageKc(usage), e)
}

func (e Des3CbcSha1Kd) VerifyChecksum(protocolKey, data, chksum []byte, usage uint32) bool {
	c, err := e.GetChecksumHash(protocolKey, data, usage)
	if err != nil {
		return false
	}
	return hmac.Equal(chksum, c)
}
