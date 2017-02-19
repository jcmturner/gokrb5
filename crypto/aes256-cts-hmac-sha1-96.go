package crypto

import (
	"crypto/aes"
	"crypto/sha1"
	"hash"
)

// RFC 3962
//+--------------------------------------------------------------------+
//|               protocol key format        128- or 256-bit string    |
//|                                                                    |
//|            string-to-key function        PBKDF2+DK with variable   |
//|                                          iteration count (see      |
//|                                          above)                    |
//|                                                                    |
//|  default string-to-key parameters        00 00 10 00               |
//|                                                                    |
//|        key-generation seed length        key size                  |
//|                                                                    |
//|            random-to-key function        identity function         |
//|                                                                    |
//|                  hash function, H        SHA-1                     |
//|                                                                    |
//|               HMAC output size, h        12 octets (96 bits)       |
//|                                                                    |
//|             message block size, m        1 octet                   |
//|                                                                    |
//|  encryption/decryption functions,        AES in CBC-CTS mode       |
//|  E and D                                 (cipher block size 16     |
//|                                          octets), with next-to-    |
//|                                          last block (last block    |
//|                                          if only one) as CBC-style |
//|                                          ivec                      |
//+--------------------------------------------------------------------+
//
//+--------------------------------------------------------------------+
//|                         encryption types                           |
//+--------------------------------------------------------------------+
//|         type name                  etype value          key size   |
//+--------------------------------------------------------------------+
//|   aes128-cts-hmac-sha1-96              17                 128      |
//|   aes256-cts-hmac-sha1-96              18                 256      |
//+--------------------------------------------------------------------+
//
//+--------------------------------------------------------------------+
//|                          checksum types                            |
//+--------------------------------------------------------------------+
//|        type name                 sumtype value           length    |
//+--------------------------------------------------------------------+
//|    hmac-sha1-96-aes128                15                   96      |
//|    hmac-sha1-96-aes256                16                   96      |
//+--------------------------------------------------------------------+

type Aes256CtsHmacSha96 struct {
}

func (e Aes256CtsHmacSha96) GetETypeID() int {
	return 18
}

func (e Aes256CtsHmacSha96) GetKeyByteSize() int {
	return 256 / 8
}

func (e Aes256CtsHmacSha96) GetKeySeedBitLength() int {
	return e.GetKeyByteSize() * 8
}

func (e Aes256CtsHmacSha96) GetHash() hash.Hash {
	return sha1.New()
}

func (e Aes256CtsHmacSha96) GetMessageBlockByteSize() int {
	return 1
}

func (e Aes256CtsHmacSha96) GetDefaultStringToKeyParams() string {
	return "00001000"
}

func (e Aes256CtsHmacSha96) GetConfounderByteSize() int {
	return aes.BlockSize
}

func (e Aes256CtsHmacSha96) GetHMACBitLength() int {
	return 96
}

func (e Aes256CtsHmacSha96) GetCypherBlockBitLength() int {
	return aes.BlockSize * 8
}

func (e Aes256CtsHmacSha96) StringToKey(secret string, salt string, s2kparams string) ([]byte, error) {
	return AESStringToKey(secret, salt, s2kparams, e)
}

func (e Aes256CtsHmacSha96) RandomToKey(b []byte) []byte {
	return AESRandomToKey(b)
}

func (e Aes256CtsHmacSha96) Encrypt(key, message []byte) ([]byte, []byte, error) {
	ivz := make([]byte, aes.BlockSize)
	return AESCTSEncrypt(key, ivz, message, e)
}

func (e Aes256CtsHmacSha96) Decrypt(key, ciphertext []byte) ([]byte, error) {
	return AESCTSDecrypt(key, ciphertext, e)
}

func (e Aes256CtsHmacSha96) DeriveKey(protocolKey, usage []byte) ([]byte, error) {
	return AESDeriveKey(protocolKey, usage, e)
}

func (e Aes256CtsHmacSha96) DeriveRandom(protocolKey, usage []byte) ([]byte, error) {
	return AESDeriveRandom(protocolKey, usage, e)
}

func (e Aes256CtsHmacSha96) VerifyIntegrity(protocolKey, ct, pt []byte, usage uint32) bool {
	return VerifyIntegrity(protocolKey, ct, pt, usage, e)
}
