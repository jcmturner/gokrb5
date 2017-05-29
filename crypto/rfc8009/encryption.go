// Encryption and checksum methods as specified in RFC 8009
package rfc8009

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/crypto/aescts"
	"github.com/jcmturner/gokrb5/crypto/common"
	"github.com/jcmturner/gokrb5/crypto/etype"
	"github.com/jcmturner/gokrb5/iana/etypeID"
)

func EncryptData(key, data []byte, e etype.EType) ([]byte, []byte, error) {
	kl := e.GetKeyByteSize()
	if e.GetETypeID() == etypeID.AES256_CTS_HMAC_SHA384_192 {
		kl = 32
	}
	if len(key) != kl {
		return []byte{}, []byte{}, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeyByteSize(), len(key))
	}
	ivz := make([]byte, aes.BlockSize)
	return aescts.Encrypt(key, ivz, data)
}

//encryption function: as follows, where E() is AES encryption in
//CBC-CS3 mode, and h is the size of truncated HMAC (128 bits or 192
//bits as described above).
//
//N = random value of length 128 bits (the AES block size)
//IV = cipher state
//C = E(Ke, N | plaintext, IV)
//H = HMAC(Ki, IV | C)
//ciphertext = C | H[1..h]
//
//Steps to compute the 128-bit cipher state:
//L = length of C in bits
//portion C into 128-bit blocks, placing any remainder of less
//than 128 bits into a final block
//if L == 128: cipher state = C
//else if L mod 128 > 0: cipher state = last full (128-bit) block
//of C (the next-to-last
//block)
//else if L mod 128 == 0: cipher state = next-to-last block of C
//
//(Note that L will never be less than 128 because of the
//presence of N in the encryption input.)
func EncryptMessage(key, message []byte, usage uint32, e etype.EType) ([]byte, []byte, error) {
	kl := e.GetKeyByteSize()
	if e.GetETypeID() == etypeID.AES256_CTS_HMAC_SHA384_192 {
		kl = 32
	}
	if len(key) != kl {
		return []byte{}, []byte{}, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", kl, len(key))
	}
	if len(key) != e.GetKeyByteSize() {
	}
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
		k, err = e.DeriveKey(key, common.GetUsageKe(usage))
		if err != nil {
			return []byte{}, []byte{}, fmt.Errorf("Error deriving key for encryption: %v", err)
		}
	}

	// Encrypt the data
	iv, b, err := e.EncryptData(k, plainBytes)
	if err != nil {
		return iv, b, fmt.Errorf("Error encrypting data: %v", err)
	}

	ivz := make([]byte, e.GetConfounderByteSize())
	ih, err := GetIntegityHash(ivz, b, key, usage, e)
	if err != nil {
		return iv, b, fmt.Errorf("Error encrypting data: %v", err)
	}
	b = append(b, ih...)
	return iv, b, nil
}

func DecryptData(key, data []byte, e etype.EType) ([]byte, error) {
	kl := e.GetKeyByteSize()
	if e.GetETypeID() == etypeID.AES256_CTS_HMAC_SHA384_192 {
		kl = 32
	}
	if len(key) != kl {
		return []byte{}, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", kl, len(key))
	}
	ivz := make([]byte, aes.BlockSize)
	return aescts.Decrypt(key, ivz, data)
}

func DecryptMessage(key, ciphertext []byte, usage uint32, e etype.EType) ([]byte, error) {
	//Derive the key
	k, err := e.DeriveKey(key, common.GetUsageKe(usage))
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

func GetIntegityHash(iv, c, key []byte, usage uint32, e etype.EType) ([]byte, error) {
	// Generate and append integrity hash
	// The HMAC is calculated over the cipher state concatenated with the
	// AES output, instead of being calculated over the confounder and
	// plaintext.  This allows the message receiver to verify the
	// integrity of the message before decrypting the message.
	// H = HMAC(Ki, IV | C)
	ib := append(iv, c...)
	return common.GetIntegrityHash(ib, key, usage, e)
}

// Verify the integrity of cipertext bytes ct.
func VerifyIntegrity(key, ct []byte, usage uint32, etype etype.EType) bool {
	h := make([]byte, etype.GetHMACBitLength()/8)
	copy(h, ct[len(ct)-etype.GetHMACBitLength()/8:])
	ivz := make([]byte, etype.GetConfounderByteSize())
	ib := append(ivz, ct[:len(ct)-(etype.GetHMACBitLength()/8)]...)
	expectedMAC, _ := common.GetIntegrityHash(ib, key, usage, etype)
	return hmac.Equal(h, expectedMAC)
}
