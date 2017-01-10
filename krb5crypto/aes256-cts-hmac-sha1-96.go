package krb5crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"strings"
)

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

const (
	s2kParamsZero = 4294967296
)

type Aes256CtsHmacSha196 struct {
}

func (e *Aes256CtsHmacSha196) GetETypeID() int {
	return 18
}

func (e *Aes256CtsHmacSha196) GetKeyByteSize() int {
	return 256 / 8
}

func (e *Aes256CtsHmacSha196) GetKeySeedBitLength() int {
	return e.GetKeyByteSize() * 8
}

func (e *Aes256CtsHmacSha196) GetHash() hash.Hash {
	return sha1.New()
}

func (e *Aes256CtsHmacSha196) GetMessageBlockByteSize() int {
	return 1
}

func (e *Aes256CtsHmacSha196) GetDefaultStringToKeyParams() string {
	return "00 00 10 00"
}

func (e *Aes256CtsHmacSha196) GetConfounderByteSize() int {
	return aes.BlockSize
}

func (e *Aes256CtsHmacSha196) GetHMACBitLength() int {
	return 96
}

func (e *Aes256CtsHmacSha196) GetCypherBlockBitLength() int {
	return aes.BlockSize * 8
}

func (e *Aes256CtsHmacSha196) StringToKey(secret string, salt string, s2kparams string) ([]byte, error) {
	//process s2kparams string
	//The parameter string is four octets indicating an unsigned
	//number in big-endian order.  This is the number of iterations to be
	//performed.  If the value is 00 00 00 00, the number of iterations to
	//be performed is 4,294,967,296 (2**32).
	var i int
	if s2kparams == "00 00 00 00" {
		i = s2kParamsZero
	} else {
		s := strings.Replace(s2kparams, " ", "", -1)
		if len(s) != 8 {
			return nil, errors.New("Invalid s2kparams")
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, errors.New("Invalid s2kparams")
		}
		buf := bytes.NewBuffer(b)
		binary.Read(buf, binary.BigEndian, &i)
		if i == 0 {
			i = s2kParamsZero
		}
	}

	return e.StringToKeyIter(secret, salt, i)
}

func (e *Aes256CtsHmacSha196) StringToPBKDF2(secret string, salt string, iterations int) []byte {
	return pbkdf2.Key([]byte(secret), []byte(salt), iterations, e.GetKeyByteSize(), sha1.New)
}

func (e *Aes256CtsHmacSha196) StringToKeyIter(secret string, salt string, iterations int) ([]byte, error) {
	tkey := e.RandomToKey(e.StringToPBKDF2(secret, salt, iterations))
	key, err := e.DeriveKey(tkey, []byte("kerberos"))
	return key, err
}

func (e *Aes256CtsHmacSha196) RandomToKey(b []byte) []byte {
	return b
}

func (e *Aes256CtsHmacSha196) DeriveRandom(protocolKey, usage []byte) ([]byte, error) {
	r, err := deriveRandom(protocolKey, usage, e.GetCypherBlockBitLength(), e.GetKeySeedBitLength(), e.Encrypt)
	return r, err
}

func (e *Aes256CtsHmacSha196) DeriveKey(protocolKey, usage []byte) ([]byte, error) {
	r, err := e.DeriveRandom(protocolKey, usage)
	if err != nil {
		return nil, err
	}
	return e.RandomToKey(r), nil
}

func (e *Aes256CtsHmacSha196) Encrypt(key, message []byte) ([]byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return nil, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeySeedBitLength(), len(key))
	}
	if len(message)%aes.BlockSize != 0 {
		message, _ = pkcs7Pad(message, e.GetMessageBlockByteSize())
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error creating cipher: %v", err)
	}

	//RFC 3961: initial cipher state      All bits zero
	iv := make([]byte, e.GetConfounderByteSize())
	//_, err = rand.Read(iv) //Not needed as all bits need to be zero

	ct := make([]byte, len(message))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, message)
	return ct, nil
}

func (e *Aes256CtsHmacSha196) Decrypt(key, ciphertext []byte) (message []byte, err error) {
	if len(key) != e.GetKeySeedBitLength() {
		err = fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeySeedBitLength(), len(key))
		return
	}
	if len(ciphertext) < aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		err = errors.New("Ciphertext is not a multiple of the block size.")
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		err = fmt.Errorf("Error creating cipher: %v", err)
		return
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(message, ciphertext)
	return
}

/*func DEwithHMAC(key, message []byte) (ct []byte, err error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", KeySize, len(key))
	}
	if len(message)%aes.BlockSize != 0 {
		return nil, errors.New("Plaintext is not a multiple of the block size")
	}

	iv := make([]byte, NonceSize)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("Error creating random nonce: %v", err)
	}

	// NewCipher only returns an error with an invalid key size,
	// but the key size was checked at the beginning of the function.
	c, err := aes.NewCipher(key[:CipherKeyLength])
	if err != nil {
		return nil, fmt.Errorf("Error creating cipher: %v", err)
	}
	ctr := cipher.NewCBCEncrypter(c, iv)
	ctr.CryptBlocks(ct, message)

	h := hmac.New(sha1.New(), key[CipherKeyLength:])
	ct = append(iv, ct...)
	h.Write(ct)
	ct = h.Sum(ct)
	return ct[:HMACKeyLength], nil
}*/
