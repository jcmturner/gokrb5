package rfc3961

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/jcmturner/gokrb5/crypto/etype"
	"golang.org/x/crypto/pbkdf2"
)

const (
	prfconstant   = "prf"
	s2kParamsZero = 4294967296
)

// RFC 3961: DR(Key, Constant) = k-truncate(E(Key, Constant, initial-cipher-state)).
//
// key: base key or protocol key. Likely to be a key from a keytab file.
//
// usage: a constant.
//
// n: block size in bits (not bytes) - note if you use something like aes.BlockSize this is in bytes.
//
// k: key length / key seed length in bits. Eg. for AES256 this value is 256.
//
// e: the encryption etype function to use.
func DeriveRandom(key, usage []byte, e etype.EType) ([]byte, error) {
	n := e.GetCypherBlockBitLength()
	k := e.GetKeySeedBitLength()
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
	_, K, err := e.EncryptData(key, nFoldUsage)
	if err != nil {
		return out, err
	}
	for i := copy(out, K); i < len(out); {
		_, K, _ = e.EncryptData(key, K)
		i = i + copy(out[i:], K)
	}
	return out, nil
}

func DeriveKey(protocolKey, usage []byte, e etype.EType) ([]byte, error) {
	r, err := e.DeriveRandom(protocolKey, usage)
	if err != nil {
		return nil, err
	}
	return e.RandomToKey(r), nil
}

func RandomToKey(b []byte) []byte {
	return b
}

func DES3RandomToKey(b []byte) []byte {
	r := stretch56Bits(b[:7])
	r2 := stretch56Bits(b[7:14])
	r = append(r, r2...)
	r3 := stretch56Bits(b[14:21])
	r = append(r, r3...)
	return r
}

func DES3StringToKey(secret, salt string, e etype.EType) ([]byte, error) {
	s := secret + salt
	tkey := e.RandomToKey(Nfold([]byte(s), e.GetKeySeedBitLength()))
	return e.DeriveKey(tkey, []byte("kerberos"))
}

func StringToKey(secret, salt, s2kparams string, e etype.EType) ([]byte, error) {
	i, err := S2KparamsToItertions(s2kparams)
	if err != nil {
		return nil, err
	}
	return StringToKeyIter(secret, salt, int(i), e)
}

func StringToPBKDF2(secret, salt string, iterations int, e etype.EType) []byte {
	return pbkdf2.Key([]byte(secret), []byte(salt), iterations, e.GetKeyByteSize(), e.GetHashFunc())
}

func StringToKeyIter(secret, salt string, iterations int, e etype.EType) ([]byte, error) {
	tkey := e.RandomToKey(StringToPBKDF2(secret, salt, iterations, e))
	return e.DeriveKey(tkey, []byte("kerberos"))
}

func PseudoRandom(key, b []byte, e etype.EType) ([]byte, error) {
	h := e.GetHashFunc()()
	h.Write(b)
	tmp := h.Sum(nil)[:e.GetMessageBlockByteSize()]
	k, err := e.DeriveKey(key, []byte(prfconstant))
	if err != nil {
		return []byte{}, err
	}
	_, prf, err := e.EncryptData(k, tmp)
	if err != nil {
		return []byte{}, err
	}
	return prf, nil
}

func S2KparamsToItertions(s2kparams string) (int, error) {
	//process s2kparams string
	//The parameter string is four octets indicating an unsigned
	//number in big-endian order.  This is the number of iterations to be
	//performed.  If the value is 00 00 00 00, the number of iterations to
	//be performed is 4,294,967,296 (2**32).
	var i uint32
	if len(s2kparams) != 8 {
		return s2kParamsZero, errors.New("Invalid s2kparams length")
	}
	b, err := hex.DecodeString(s2kparams)
	if err != nil {
		return s2kParamsZero, errors.New("Invalid s2kparams, cannot decode string to bytes")
	}
	i = binary.BigEndian.Uint32(b)
	//buf := bytes.NewBuffer(b)
	//err = binary.Read(buf, binary.BigEndian, &i)
	if err != nil {
		return s2kParamsZero, errors.New("Invalid s2kparams, cannot convert to big endian int32")
	}
	return int(i), nil
}

func stretch56Bits(b []byte) []byte {
	d := make([]byte, len(b), len(b))
	copy(d, b)
	var lb byte
	for i, v := range d {
		bv, nb := calcEvenParity(v)
		d[i] = nb
		if bv != 0 {
			lb = lb | (1 << uint(i+1))
		} else {
			lb = lb &^ (1 << uint(i+1))
		}
	}
	_, lb = calcEvenParity(lb)
	d = append(d, lb)
	return d
}

func calcEvenParity(b byte) (uint8, uint8) {
	lowestbit := b & 0x01
	// c counter of 1s in the first 7 bits of the byte
	var c int
	// Iterate over the highest 7 bits (hence p starts at 1 not zero) and count the 1s.
	for p := 1; p < 8; p++ {
		v := b & (1 << uint(p))
		if v != 0 {
			c += 1
		}
	}
	if c%2 == 0 {
		//Even number of 1s so set parity to 1
		b = b | 1
	} else {
		//Odd number of 1s so set parity to 0
		b = b &^ 1
	}
	return lowestbit, b
}
