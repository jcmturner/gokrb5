package crypto

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/types"
	"hash"
	"encoding/hex"
)

type EType interface {
	GetETypeID() int
	GetKeyByteSize() int                                        // See "protocol key format" for defined values
	GetKeySeedBitLength() int                                   // key-generation seed length, k
	GetDefaultStringToKeyParams() string                        // default string-to-key parameters (s2kparams)
	StringToKey(string, salt, s2kparams string) ([]byte, error) // string-to-key (UTF-8 string, UTF-8 string, opaque)->(protocol-key)
	RandomToKey(b []byte) []byte                                // random-to-key (bitstring[K])->(protocol-key)
	GetHMACBitLength() int                                      // HMAC output size, h
	GetMessageBlockByteSize() int                               // message block size, m
	Encrypt(key, message []byte) ([]byte, []byte, error)        // E function - encrypt (specific-key, state, octet string)->(state, octet string)
	Decrypt(key, ciphertext []byte) ([]byte, error)             // D function
	GetCypherBlockBitLength() int                               // cipher block size, c
	GetConfounderByteSize() int                                 // This is the same as the cipher block size but in bytes.
	DeriveKey(protocolKey, usage []byte) ([]byte, error)        // DK key-derivation (protocol-key, integer)->(specific-key)
	DeriveRandom(protocolKey, usage []byte) ([]byte, error)     // DR pseudo-random (protocol-key, octet-string)->(octet-string)
	VerifyChecksum(protocolKey, ct, pt []byte, usage int) bool
	GetHash() hash.Hash
}

func GetEtype(id int) (EType, error) {
	switch id {
	case 17:
		var et Aes128CtsHmacSha96
		return et, nil
	case 18:
		var et Aes256CtsHmacSha96
		return et, nil
	default:
		return nil, fmt.Errorf("Unknown or unsupported EType: %d", id)
	}
}

// RFC3961: DR(Key, Constant) = k-truncate(E(Key, Constant, initial-cipher-state))
// key - base key or protocol key. Likely to be a key from a keytab file
// TODO usage - a constant
// n - block size in bits (not bytes) - note if you use something like aes.BlockSize this is in bytes.
// k - key length / key seed length in bits. Eg. for AES256 this value is 256
// encrypt - the encryption function to use
func deriveRandom(key, usage []byte, n, k int, e EType) ([]byte, error) {
	//Ensure the usage constant is at least the size of the cypher block size. Pass it through the nfold algorithm that will "stretch" it if needs be.
	nFoldUsage := Nfold(usage, n)
	//k-truncate implemented by creating a byte array the size of k (k is in bits hence /8)
	out := make([]byte, k/8)

	/*If the output	of E is shorter than k bits, it is fed back into the encryption as many times as necessary.
	The construct is as follows (where | indicates concatentation):

	K1 = E(Key, n-fold(Constant), initial-cipher-state)
	K2 = E(Key, K1, initial-cipher-state)
	K3 = E(Key, K2, initial-cipher-state)
	K4 = ...

	DR(Key, Constant) = k-truncate(K1 | K2 | K3 | K4 ...)*/
	_, K, err := e.Encrypt(key, nFoldUsage)
	if err != nil {
		return out, err
	}
	for i := copy(out, K); i < len(out); {
		_, K, _ = e.Encrypt(key, K)
		i = i + copy(out[i:], K)
	}
	return out, nil
}

func zeroPad(b []byte, m int) ([]byte, error) {
	if m <= 0 {
		return nil, errors.New("Invalid message block size when padding")
	}
	if b == nil || len(b) == 0 {
		return nil, errors.New("Data not valid to pad: Zero size")
	}
	if l := len(b) % m; l != 0 {
		n := m - l
		z := make([]byte, n)
		b = append(b, z...)
	}
	return b, nil
}

func pkcs7Pad(b []byte, m int) ([]byte, error) {
	if m <= 0 {
		return nil, errors.New("Invalid message block size when padding")
	}
	if b == nil || len(b) == 0 {
		return nil, errors.New("Data not valid to pad: Zero size")
	}
	n := m - (len(b) % m)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

func pkcs7Unpad(b []byte, m int) ([]byte, error) {
	if m <= 0 {
		return nil, errors.New("Invalid message block size when unpadding")
	}
	if b == nil || len(b) == 0 {
		return nil, errors.New("Padded data not valid: Zero size")
	}
	if len(b)%m != 0 {
		return nil, errors.New("Padded data not valid: Not multiple of message block size")
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, errors.New("Padded data not valid: Data may not have been padded")
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, errors.New("Padded data not valid")
		}
	}
	return b[:len(b)-n], nil
}

func DecryptEncPart(key []byte, pe types.EncryptedData, etype EType, usage uint32) ([]byte, error) {
	//Derive the key
	//TODO need to consider PAdata for deriving key
	k, err := etype.DeriveKey(key, GetUsageKe(usage))
	if err != nil {
		return nil, fmt.Errorf("Error deriving key: %v", err)
	}
	// Strip off the checksum from the end
	b, err := etype.Decrypt(k, pe.Cipher[:len(pe.Cipher)-etype.GetHMACBitLength()/8])
	if err != nil {
		return nil, fmt.Errorf("Error decrypting: %v", err)
	}
	//Verify checksum
	if !etype.VerifyChecksum(key, pe.Cipher, b, int(usage)) {
		return nil, errors.New("Error decrypting encrypted part: checksum verification failed")
	}
	//Remove the confounder bytes
	b = b[etype.GetConfounderByteSize():]
	if err != nil {
		return nil, fmt.Errorf("Error decrypting encrypted part: %v", err)
	}
	return b, nil
}

func GetKeyFromPassword(passwd string, cn types.PrincipalName, realm string, etypeId int, pas types.PADataSequence) ([]byte, EType, error) {
	var key []byte
	var etype EType
	for _, pa := range pas {
		if pa.PADataType == 19 {
			var et2 types.ETypeInfo2
			err := et2.Unmarshal(pa.PADataValue)
			if err != nil {
				return key, etype, fmt.Errorf("Error unmashalling PA Data to PA-ETYPE-INFO2: %v", err)
			}
			etype, err := GetEtype(et2[0].EType)
			if err != nil {
				return key, etype, fmt.Errorf("Error getting encryption type: %v", err)
			}
			sk2p := etype.GetDefaultStringToKeyParams()
			if len(et2[0].S2KParams) == 8 {
				sk2p = hex.EncodeToString(et2[0].S2KParams)
			}
			key, err := etype.StringToKey(passwd, et2[0].Salt, sk2p)
			if err != nil {
				return key, etype, fmt.Errorf("Error deriving key from string: %+v", err)
			}
			return key, etype, nil
		}
	}
	etype, err := GetEtype(etypeId)
	if err != nil {
		return key, etype, fmt.Errorf("Error getting encryption type: %v", err)
	}
	sk2p := etype.GetDefaultStringToKeyParams()
	key, err = etype.StringToKey(passwd, cn.GetSalt(realm), sk2p)
	if err != nil {
		return key, etype, fmt.Errorf("Error deriving key from string: %+v", err)
	}
	return key, etype, nil
}

func GetChecksum(pt, key []byte, usage int, etype EType) ([]byte, error) {
	k, err := etype.DeriveKey(key, GetUsageKi(uint32(usage)))
	if err != nil {
		return nil, fmt.Errorf("Unable to derive key for checksum: %v", err)
	}
	mac := hmac.New(etype.GetHash, k)
	//TODO do I need to append the ivz before taking the hash?
	//ivz := make([]byte, etype.GetConfounderByteSize())
	//pt = append(ivz, pt...)
	//if r := len(pt)%etype.GetMessageBlockByteSize(); r != 0 {
	//	t := make([]byte, etype.GetMessageBlockByteSize() - r)
	//	pt = append(pt, t...)
	//}
	mac.Write(pt)
	return mac.Sum(nil), nil
}

func VerifyChecksum(key, ct, pt []byte, usage int, etype EType) bool {
	//The ciphertext output is the concatenation of the output of the basic
	//encryption function E and a (possibly truncated) HMAC using the
	//specified hash function H, both applied to the plaintext with a
	//random confounder prefix and sufficient padding to bring it to a
	//multiple of the message block size.  When the HMAC is computed, the
	//key is used in the protocol key form.
	h := ct[len(ct)-etype.GetHMACBitLength()/8+1:]
	expectedMAC, _ := GetChecksum(pt, key, usage, etype)
	return hmac.Equal(h, expectedMAC[1:etype.GetHMACBitLength()/8])
}

/*
Key Usage Numbers

RFC 3961: The "well-known constant" used for the DK function is the key usage number, expressed as four octets in big-endian order, followed by one octet indicated below.

Kc = DK(base-key, usage | 0x99);
Ke = DK(base-key, usage | 0xAA);
Ki = DK(base-key, usage | 0x55);
*/

// un - usage number
func GetUsageKc(un uint32) []byte {
	return getUsage(un, 0x99)
}

// un - usage number
func GetUsageKe(un uint32) []byte {
	return getUsage(un, 0xAA)
}

// un - usage number
func GetUsageKi(un uint32) []byte {
	return getUsage(un, 0x55)
}

func getUsage(un uint32, o byte) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, un)
	return append(buf.Bytes(), o)
}
