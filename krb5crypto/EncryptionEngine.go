package krb5crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type EType interface {
	GetETypeID() int
	GetKeyByteSize() int // See protocol key format for defined values
	StringToKey(string, salt string, s2kparams []byte) (protocolKey []byte)
	GetDefaultStringToKeyParams() string // s2kparams
	GetKeySeedBitLength() int            // key-generation seed length, k
	RandomToKey(b []byte) (protocolKey []byte)
	GetHMACBitLength() int                                      // HMAC output size, h
	GetMessageBlockByteSize() int                               // message block size, m
	Encrypt(key, message []byte) (ct []byte, err error)         // E function
	Decrypt(key, ciphertext []byte) (message []byte, err error) // D function
	GetCypherBlockBitLength() int                               // cipher block size, c
	GetConfounderByteSize() int                                 // This is the same as the cipher block size but in bytes.
	DeriveKey(protocolKey, usage []byte) (specificKey []byte)   // DK
	DeriveRandom(protocolKey, usage []byte) ([]byte, error)     // DR
}
type encryptFunc func([]byte, []byte) ([]byte, error)

// RFC3961: DR(Key, Constant) = k-truncate(E(Key, Constant, initial-cipher-state))
// key - base key or protocol key. Likely to be a key from a keytab file
// TODO usage - a constant
// n - block size in bits (not bytes) - note if you use something like aes.BlockSize this is in bytes.
// k - key length / key seed length in bits. Eg. for AES256 this value is 256
// encrypt - the encryption function to use
func deriveRandom(key, usage []byte, n, k int, encrypt encryptFunc) ([]byte, error) {
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
	K, err := encrypt(key, nFoldUsage)
	if err != nil {
		return out, err
	}
	for i := copy(out, K); i < len(out); {
		K, _ = encrypt(key, K)
		i = i + copy(out[i:], K)
	}
	return out, nil
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

var KeyUsageNumbers map[int]string = map[int]string{
	1:    "AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the client key",
	2:    "AS-REP Ticket and TGS-REP Ticket (includes TGS session key or application session key), encrypted with the service key",
	3:    "AS-REP encrypted part (includes TGS session key or application session key), encrypted with the client key",
	4:    "TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with the TGS session key",
	5:    "TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with the TGS authenticator subkey",
	6:    "TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator cksum, keyed with the TGS session key",
	7:    "TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes TGS authenticator subkey), encrypted with the TGS session key",
	8:    "TGS-REP encrypted part (includes application session key), encrypted with the TGS session key",
	9:    "TGS-REP encrypted part (includes application session key), encrypted with the TGS authenticator subkey",
	10:   "AP-REQ Authenticator cksum, keyed with the application session key",
	11:   "AP-REQ Authenticator (includes application authenticator subkey), encrypted with the application session key",
	12:   "AP-REP encrypted part (includes application session subkey), encrypted with the application session key",
	13:   "KRB-PRIV encrypted part, encrypted with a key chosen by the application",
	14:   "KRB-CRED encrypted part, encrypted with a key chosen by the application",
	15:   "KRB-SAFE cksum, keyed with a key chosen by the application",
	19:   "AD-KDC-ISSUED checksum",
	1024: "Encryption for application use in protocols that do not specify key usage values",
}
