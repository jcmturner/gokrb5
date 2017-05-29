// Encryption and checksum methods as specified in RFC 3961
package rfc3961

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/crypto/aescts"
	"github.com/jcmturner/gokrb5/crypto/common"
	"github.com/jcmturner/gokrb5/crypto/etype"
)

func EncryptData(key, data []byte, e etype.EType) ([]byte, []byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return []byte{}, []byte{}, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeyByteSize(), len(key))
	}
	ivz := make([]byte, aes.BlockSize)
	return aescts.Encrypt(key, ivz, data)
}

func EncryptMessage(key, message []byte, usage uint32, e etype.EType) ([]byte, []byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return []byte{}, []byte{}, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeyByteSize(), len(key))
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

	// Generate and append integrity hash
	ih, err := common.GetIntegrityHash(plainBytes, key, usage, e)
	if err != nil {
		return iv, b, fmt.Errorf("Error encrypting data: %v", err)
	}
	b = append(b, ih...)
	return iv, b, nil
}

func DecryptData(key, data []byte, e etype.EType) ([]byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return []byte{}, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeyByteSize(), len(key))
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

// Verify the integrity of cipertext bytes ct.
func VerifyIntegrity(key, ct, pt []byte, usage uint32, etype etype.EType) bool {
	//The ciphertext output is the concatenation of the output of the basic
	//encryption function E and a (possibly truncated) HMAC using the
	//specified hash function H, both applied to the plaintext with a
	//random confounder prefix and sufficient padding to bring it to a
	//multiple of the message block size.  When the HMAC is computed, the
	//key is used in the protocol key form.
	h := make([]byte, etype.GetHMACBitLength()/8)
	copy(h, ct[len(ct)-etype.GetHMACBitLength()/8:])
	expectedMAC, _ := common.GetIntegrityHash(pt, key, usage, etype)
	return hmac.Equal(h, expectedMAC)
}
