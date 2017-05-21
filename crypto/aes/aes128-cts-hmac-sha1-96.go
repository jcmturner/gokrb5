package aes

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/crypto/engine"
	"github.com/jcmturner/gokrb5/iana/chksumtype"
	"github.com/jcmturner/gokrb5/iana/etypeID"
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

type Aes128CtsHmacSha96 struct {
}

func (e Aes128CtsHmacSha96) GetETypeID() int {
	return etypeID.AES128_CTS_HMAC_SHA1_96
}

func (e Aes128CtsHmacSha96) GetHashID() int {
	return chksumtype.HMAC_SHA1_96_AES128
}

func (e Aes128CtsHmacSha96) GetKeyByteSize() int {
	return 128 / 8
}

func (e Aes128CtsHmacSha96) GetKeySeedBitLength() int {
	return e.GetKeyByteSize() * 8
}

func (e Aes128CtsHmacSha96) GetHash() func() hash.Hash {
	return sha1.New
}

func (e Aes128CtsHmacSha96) GetMessageBlockByteSize() int {
	return 1
}

func (e Aes128CtsHmacSha96) GetDefaultStringToKeyParams() string {
	return "00001000"
}

func (e Aes128CtsHmacSha96) GetConfounderByteSize() int {
	return aes.BlockSize
}

func (e Aes128CtsHmacSha96) GetHMACBitLength() int {
	return 96
}

func (e Aes128CtsHmacSha96) GetCypherBlockBitLength() int {
	return aes.BlockSize * 8
}

func (e Aes128CtsHmacSha96) StringToKey(secret string, salt string, s2kparams string) ([]byte, error) {
	return stringToKey(secret, salt, s2kparams, e)
}

func (e Aes128CtsHmacSha96) RandomToKey(b []byte) []byte {
	return randomToKey(b)
}

func (e Aes128CtsHmacSha96) EncryptData(key, data []byte) ([]byte, []byte, error) {
	ivz := make([]byte, aes.BlockSize)
	return encryptCTS(key, ivz, data, e)
}

func (e Aes128CtsHmacSha96) EncryptMessage(key, message []byte, usage uint32) ([]byte, []byte, error) {
	//confounder
	c := make([]byte, e.GetConfounderByteSize())
	_, err := rand.Read(c)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf("Could not generate random confounder: %v", err)
	}
	plainBytes := append(c, message...)

	// Derive key for encryption from usage
	var k []byte
	if usage != 0 {
		k, err = e.DeriveKey(key, engine.GetUsageKe(usage))
		if err != nil {
			return []byte{}, []byte{}, fmt.Errorf("Error deriving key for encryption: %v", err)
		}
	}

	// Encrypt the data
	iv, b, err := e.EncryptData(k, plainBytes)
	if err != nil {
		return iv, b, fmt.Errorf("Error encrypting data: %v", err)
	}

	// Generate and append integrity hash
	ih, err := engine.GetIntegrityHash(plainBytes, key, usage, e)
	if err != nil {
		return iv, b, fmt.Errorf("Error encrypting data: %v", err)
	}
	b = append(b, ih...)
	return iv, b, nil
}

func (e Aes128CtsHmacSha96) DecryptData(key, data []byte) ([]byte, error) {
	return decryptCTS(key, data, e)
}

func (e Aes128CtsHmacSha96) DecryptMessage(key, ciphertext []byte, usage uint32) ([]byte, error) {
	//Derive the key
	k, err := e.DeriveKey(key, engine.GetUsageKe(usage))
	if err != nil {
		return nil, fmt.Errorf("Error deriving key: %v", err)
	}
	// Strip off the checksum from the end
	b, err := e.DecryptData(k, ciphertext[:len(ciphertext)-e.GetHMACBitLength()/8])
	if err != nil {
		return nil, err
	}
	//Verify checksum
	if !e.VerifyIntegrity(key, ciphertext, b, usage) {
		return nil, errors.New("Integrity verification failed")
	}
	//Remove the confounder bytes
	return b[e.GetConfounderByteSize():], nil
}

func (e Aes128CtsHmacSha96) DeriveKey(protocolKey, usage []byte) ([]byte, error) {
	return deriveKey(protocolKey, usage, e)
}

func (e Aes128CtsHmacSha96) DeriveRandom(protocolKey, usage []byte) ([]byte, error) {
	return deriveRandom(protocolKey, usage, e)
}

func (e Aes128CtsHmacSha96) VerifyIntegrity(protocolKey, ct, pt []byte, usage uint32) bool {
	return engine.VerifyIntegrity(protocolKey, ct, pt, usage, e)
}
