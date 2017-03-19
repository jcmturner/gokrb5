package engine

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/crypto/etype"
)

// RFC3961: DR(Key, Constant) = k-truncate(E(Key, Constant, initial-cipher-state))
// key - base key or protocol key. Likely to be a key from a keytab file
// usage - a constant
// n - block size in bits (not bytes) - note if you use something like aes.BlockSize this is in bytes.
// k - key length / key seed length in bits. Eg. for AES256 this value is 256
// encrypt - the encryption function to use
func DeriveRandom(key, usage []byte, n, k int, e etype.EType) ([]byte, error) {
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

func ZeroPad(b []byte, m int) ([]byte, error) {
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

func PKCS7Pad(b []byte, m int) ([]byte, error) {
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

func PKCS7Unpad(b []byte, m int) ([]byte, error) {
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

func getHash(pt, key []byte, usage []byte, etype etype.EType) ([]byte, error) {
	k, err := etype.DeriveKey(key, usage)
	if err != nil {
		return nil, fmt.Errorf("Unable to derive key for checksum: %v", err)
	}
	mac := hmac.New(etype.GetHash, k)
	p := make([]byte, len(pt))
	copy(p, pt)
	mac.Write(p)
	return mac.Sum(nil)[:etype.GetHMACBitLength()/8], nil
}

func GetChecksumHash(pt, key []byte, usage uint32, etype etype.EType) ([]byte, error) {
	return getHash(pt, key, GetUsageKc(usage), etype)
}

func GetIntegrityHash(pt, key []byte, usage uint32, etype etype.EType) ([]byte, error) {
	return getHash(pt, key, GetUsageKi(usage), etype)
}

func VerifyIntegrity(key, ct, pt []byte, usage uint32, etype etype.EType) bool {
	//The ciphertext output is the concatenation of the output of the basic
	//encryption function E and a (possibly truncated) HMAC using the
	//specified hash function H, both applied to the plaintext with a
	//random confounder prefix and sufficient padding to bring it to a
	//multiple of the message block size.  When the HMAC is computed, the
	//key is used in the protocol key form.
	h := make([]byte, etype.GetHMACBitLength()/8)
	copy(h, ct[len(ct)-etype.GetHMACBitLength()/8:])
	expectedMAC, _ := GetIntegrityHash(pt, key, usage, etype)
	return hmac.Equal(h, expectedMAC)
}

func VerifyChecksum(key, chksum, msg []byte, usage uint32, etype etype.EType) bool {
	//The ciphertext output is the concatenation of the output of the basic
	//encryption function E and a (possibly truncated) HMAC using the
	//specified hash function H, both applied to the plaintext with a
	//random confounder prefix and sufficient padding to bring it to a
	//multiple of the message block size.  When the HMAC is computed, the
	//key is used in the protocol key form.
	expectedMAC, _ := GetChecksumHash(msg, key, usage, etype)
	return hmac.Equal(chksum, expectedMAC)
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
