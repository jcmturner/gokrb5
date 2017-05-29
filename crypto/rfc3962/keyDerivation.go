// Encryption and checksum methods as specified in RFC 3962
package rfc3962

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const (
	s2kParamsZero = 4294967296
)

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
