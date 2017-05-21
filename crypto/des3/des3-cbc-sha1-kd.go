// DES3 Kerberos Encryption Types.
package des3

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/crypto/engine"
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

func (e Des3CbcSha1Kd) GetHash() func() hash.Hash {
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
	return e.GetHash()().Size()
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
	r, err := engine.DeriveRandom(protocolKey, usage, e.GetCypherBlockBitLength(), e.GetKeySeedBitLength(), e)
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
	if len(key) != e.GetKeyByteSize() {
		return nil, nil, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeySeedBitLength(), len(key))

	}
	data, _ = engine.ZeroPad(data, e.GetMessageBlockByteSize())

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("Error creating cipher: %v", err)
	}

	//RFC 3961: initial cipher state      All bits zero
	ivz := make([]byte, e.GetConfounderByteSize())

	ct := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, ivz)
	mode.CryptBlocks(ct, data)
	return ivz, ct, nil
}

func (e Des3CbcSha1Kd) EncryptMessage(key, message []byte, usage uint32) ([]byte, []byte, error) {
	//confounder
	c := make([]byte, e.GetConfounderByteSize())
	_, err := rand.Read(c)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf("Could not generate random confounder: %v", err)
	}
	plainBytes := append(c, message...)

	iv, b, err := e.EncryptData(key, plainBytes)
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

func (e Des3CbcSha1Kd) DecryptData(key, data []byte) ([]byte, error) {
	if len(key) != e.GetKeySeedBitLength() {
		return []byte{}, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeySeedBitLength(), len(key))
	}

	if len(data) < des.BlockSize || len(data)%des.BlockSize != 0 {
		return []byte{}, errors.New("Ciphertext is not a multiple of the block size.")
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return []byte{}, fmt.Errorf("Error creating cipher: %v", err)
	}
	pt := make([]byte, len(data))
	ivz := make([]byte, e.GetConfounderByteSize())
	mode := cipher.NewCBCDecrypter(block, ivz)
	mode.CryptBlocks(pt, data)
	return pt, nil
}

func (e Des3CbcSha1Kd) DecryptMessage(key, ciphertext []byte, usage uint32) (message []byte, err error) {
	// Strip off the checksum from the end
	b, err := e.DecryptData(key, ciphertext[:len(ciphertext)-e.GetHMACBitLength()/8])
	if err != nil {
		return nil, fmt.Errorf("Error decrypting: %v", err)
	}
	//Verify checksum
	if !e.VerifyIntegrity(key, ciphertext, b, usage) {
		return nil, errors.New("Error decrypting: integrity verification failed")
	}
	//Remove the confounder bytes
	return b[e.GetConfounderByteSize():], nil
}

func (e Des3CbcSha1Kd) VerifyIntegrity(protocolKey, ct, pt []byte, usage uint32) bool {
	return engine.VerifyIntegrity(protocolKey, ct, pt, usage, e)
}
