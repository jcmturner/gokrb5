package krb5crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

const (
	CipherKeyLength = 256 // AES256
	HMACKeyLength   = 96  // SHA96
	KeySize         = 352 // CipherKeyLength + HMACKeyLength
	NonceSize       = aes.BlockSize
)

func StringToKey(secret string, salt string, s2kparams []byte) (protocolKey []byte) {
	return
}

func RandomToKey(b []byte) (protocolKey []byte) {
	return
}

func DeriveKey(protocolKey, usage []byte) (specificKey []byte) {
	e := Encrypt
	r, _ := deriveRandom(protocolKey, usage, aes.BlockSize * 8, CipherKeyLength, e)
	return r
}

func Encrypt(key, message []byte) (ct []byte, err error) {
	if len(key) != KeySize {
		err = fmt.Errorf("Incorrect keysize: expected: %v actual: %v", KeySize, len(key))
		return
	}
	if len(message)%aes.BlockSize != 0 {
		err = errors.New("Plaintext is not a multiple of the block size. Padding may be needed.")
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		err = fmt.Errorf("Error creating cipher: %v", err)
		return
	}

	//RFC 3961: initial cipher state      All bits zero
	iv := make([]byte, NonceSize)
	//_, err = rand.Read(iv) //Not needed as all bits need to be zero
	if err != nil {
		err = fmt.Errorf("Error creating random nonce/initial state: %v", err)
		return
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, message)
	return
}

func Decrypt(key, ciphertext []byte) (message []byte, err error) {
	if len(key) != KeySize {
		err = fmt.Errorf("Incorrect keysize: expected: %v actual: %v", KeySize, len(key))
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
