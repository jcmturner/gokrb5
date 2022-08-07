package rfc3962

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"strconv"

	"github.com/jcmturner/gokrb5/v8/crypto/etype"
	"golang.org/x/crypto/pbkdf2"
)

const (
	s2kParamsZero = 4294967296
)

// StringToKey returns a key derived from the string provided according to the definition in RFC 3961.
func StringToKey(secret, salt, s2kparams string, e etype.EType) ([]byte, error) {
	i, err := S2KparamsToItertions(s2kparams)
	if err != nil {
		return nil, err
	}
	return StringToKeyIter(secret, salt, i, e)
}

// StringToPBKDF2 generates an encryption key from a pass phrase and salt string using the PBKDF2 function from PKCS #5 v2.0
func StringToPBKDF2(secret, salt string, iterations int, e etype.EType) []byte {
	return pbkdf2.Key([]byte(secret), []byte(salt), iterations, e.GetKeyByteSize(), e.GetHashFunc())
}

// StringToKeyIter returns a key derived from the string provided according to the definition in RFC 3961.
func StringToKeyIter(secret, salt string, iterations int, e etype.EType) ([]byte, error) {
	tkey := e.RandomToKey(StringToPBKDF2(secret, salt, iterations, e))
	return e.DeriveKey(tkey, []byte("kerberos"))
}

// S2KparamsToItertions converts the string representation of iterations to an integer
func S2KparamsToItertions(s2kparams string) (int, error) {
	//The s2kparams string should be hex string representing 4 bytes
	//The 4 bytes represent a number in big endian order
	//If the value is zero then the number of iterations should be 4,294,967,296 (2^32)
	//However for 32bit systems we use the max 32-bit integer value as 2^32 exceeds the max size of a 32-bit integer and
	//the Go pbkdf2 package takes an int argument rather than an int64.
	var i uint32
	if len(s2kparams) != 8 {
		var zeroDefault int64 = math.MaxInt32
		if strconv.IntSize > 32 {
			zeroDefault = s2kParamsZero
		}
		return int(zeroDefault), errors.New("invalid s2kparams length")
	}
	b, err := hex.DecodeString(s2kparams)
	if err != nil {
		var zeroDefault int64 = math.MaxInt32
		if strconv.IntSize > 32 {
			zeroDefault = s2kParamsZero
		}
		return int(zeroDefault), errors.New("invalid s2kparams, cannot decode string to bytes")
	}
	i = binary.BigEndian.Uint32(b)
	return int(i), nil
}
