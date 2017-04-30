// Partial implementation of NDR encoding: http://pubs.opengroup.org/onlinepubs/9629399/chap14.htm
package ndr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
)

/*
Serialization Version 1
https://msdn.microsoft.com/en-us/library/cc243563.aspx

Common Header - https://msdn.microsoft.com/en-us/library/cc243890.aspx
8 bytes in total:
- First byte - Version: Must equal 1
- Second byte -  1st 4 bits: Endianess (0=Big; 1=Little); 2nd 4 bits: Character Encoding (0=ASCII; 1=EBCDIC)
- 3rd - Floating point representation
- 4th - Common Header Length: Must equal 8
- 5th - 8th - Filler: MUST be set to 0xcccccccc on marshaling, and SHOULD be ignored during unmarshaling.

Private Header - https://msdn.microsoft.com/en-us/library/cc243919.aspx
8 bytes in total:
- First 4 bytes - Indicates the length of a serialized top-level type in the octet stream. It MUST include the padding length and exclude the header itself.
- Second 4 bytes - Filler: MUST be set to 0 (zero) during marshaling, and SHOULD be ignored during unmarshaling.
*/

const (
	PROTOCOL_VERSION     = 1
	COMMON_HEADER_BYTES  = 8
	PRIVATE_HEADER_BYTES = 8
	BIG_ENDIAN           = 0
	LITTLE_ENDIAN        = 1
	ASCII                = 0
	EBCDIC               = 1
	IEEE                 = 0
	VAX                  = 1
	CRAY                 = 2
	IBM                  = 3
)

type CommonHeader struct {
	Version           uint8
	Endianness        binary.ByteOrder
	CharacterEncoding uint8
	//FloatRepresentation uint8
	HeaderLength uint16
	Filler       []byte
}

type PrivateHeader struct {
	ObjectBufferLength uint32
	Filler             []byte
}

func ReadHeaders(b *[]byte) (CommonHeader, PrivateHeader, int, error) {
	ch, p, err := GetCommonHeader(b)
	if err != nil {
		return CommonHeader{}, PrivateHeader{}, 0, err
	}
	ph, err := GetPrivateHeader(b, &p, &ch.Endianness)
	if err != nil {
		return CommonHeader{}, PrivateHeader{}, 0, err
	}
	return ch, ph, p, err
}

func GetCommonHeader(b *[]byte) (CommonHeader, int, error) {
	//The first 8 bytes comprise the Common RPC Header for type marshalling.
	if len(*b) < COMMON_HEADER_BYTES {
		return CommonHeader{}, 0, NDRMalformed{EText: "Not enough bytes."}
	}
	if (*b)[0] != PROTOCOL_VERSION {
		return CommonHeader{}, 0, NDRMalformed{EText: fmt.Sprintf("Stream does not indicate a RPC Type serialization of version %v", PROTOCOL_VERSION)}
	}
	endian := int((*b)[1] >> 4 & 0xF)
	if endian != 0 && endian != 1 {
		return CommonHeader{}, 1, NDRMalformed{EText: "Common header does not indicate a valid endianness"}
	}
	charEncoding := uint8((*b)[1] & 0xF)
	if charEncoding != 0 && charEncoding != 1 {
		return CommonHeader{}, 1, NDRMalformed{EText: "Common header does not indicate a valid charater encoding"}
	}
	var bo binary.ByteOrder
	switch endian {
	case LITTLE_ENDIAN:
		bo = binary.LittleEndian
	case BIG_ENDIAN:
		bo = binary.BigEndian
	}
	l := bo.Uint16((*b)[2:4])
	if l != COMMON_HEADER_BYTES {
		return CommonHeader{}, 4, NDRMalformed{EText: fmt.Sprintf("Common header does not indicate a valid length: %v instead of %v", uint8((*b)[3]), COMMON_HEADER_BYTES)}
	}

	return CommonHeader{
		Version:           uint8((*b)[0]),
		Endianness:        bo,
		CharacterEncoding: charEncoding,
		//FloatRepresentation: uint8(b[2]),
		HeaderLength: l,
		Filler:       (*b)[4:8],
	}, 8, nil
}

func GetPrivateHeader(b *[]byte, p *int, bo *binary.ByteOrder) (PrivateHeader, error) {
	//The next 8 bytes comprise the RPC type marshalling private header for constructed types.
	if len(*b) < (PRIVATE_HEADER_BYTES) {
		return PrivateHeader{}, NDRMalformed{EText: "Not enough bytes."}
	}
	var l uint32
	buf := bytes.NewBuffer((*b)[*p : *p+4])
	binary.Read(buf, *bo, &l)
	if l%8 != 0 {
		return PrivateHeader{}, NDRMalformed{EText: "Object buffer length not a multiple of 8"}
	}
	*p += 8
	return PrivateHeader{
		ObjectBufferLength: l,
		Filler:             (*b)[4:8],
	}, nil
}

// Read bytes representing a thirty two bit integer.
func Read_uint8(b *[]byte, p *int) (i uint8) {
	if len((*b)[*p:]) < 1 {
		return
	}
	ensureAlignment(p, 1)
	i = uint8((*b)[*p])
	*p += 1
	return
}

// Read bytes representing a thirty two bit integer.
func Read_uint16(b *[]byte, p *int, e *binary.ByteOrder) (i uint16) {
	if len((*b)[*p:]) < 2 {
		return
	}
	ensureAlignment(p, 2)
	i = (*e).Uint16((*b)[*p : *p+2])
	*p += 2
	return
}

// Read bytes representing a thirty two bit integer.
func Read_uint32(b *[]byte, p *int, e *binary.ByteOrder) (i uint32) {
	if len((*b)[*p:]) < 4 {
		return
	}
	ensureAlignment(p, 4)
	i = (*e).Uint32((*b)[*p : *p+4])
	*p += 4
	return
}

// Read bytes representing a thirty two bit integer.
func Read_uint64(b *[]byte, p *int, e *binary.ByteOrder) (i uint64) {
	if len((*b)[*p:]) < 8 {
		return
	}
	ensureAlignment(p, 8)
	i = (*e).Uint64((*b)[*p : *p+8])
	*p += 8
	return
}

func Read_bytes(b *[]byte, p *int, s int, e *binary.ByteOrder) (r []byte) {
	if len((*b)[*p:]) < s {
		return
	}
	buf := bytes.NewBuffer((*b)[*p : *p+s])
	r = make([]byte, s)
	binary.Read(buf, *e, &r)
	*p += s
	return r
}

func Read_bool(b *[]byte, p *int) bool {
	if len((*b)[*p:]) < 1 {
		return false
	}
	if Read_uint8(b, p) != 0 {
		return true
	}
	return false
}

func Read_IEEEfloat32(b *[]byte, p *int, e *binary.ByteOrder) float32 {
	ensureAlignment(p, 4)
	return math.Float32frombits(Read_uint32(b, p, e))
}

func Read_IEEEfloat64(b *[]byte, p *int, e *binary.ByteOrder) float64 {
	ensureAlignment(p, 8)
	return math.Float64frombits(Read_uint64(b, p, e))
}

// Conformant and Varying Strings
// A conformant and varying string is a string in which the maximum number of elements is not known beforehand and therefore is included in the representation of the string.
// NDR represents a conformant and varying string as an ordered sequence of representations of the string elements, preceded by three unsigned long integers.
// The first integer gives the maximum number of elements in the string, including the terminator.
// The second integer gives the offset from the first index of the string to the first index of the actual subset being passed.
// The third integer gives the actual number of elements being passed, including the terminator.
func Read_ConformantVaryingString(b *[]byte, p *int, e *binary.ByteOrder) (string, error) {
	m := Read_uint32(b, p, e) // Max element count
	o := Read_uint32(b, p, e) // Offset
	a := Read_uint32(b, p, e) // Actual count
	if a > (m-o) || o > m {
		return "", NDRMalformed{EText: fmt.Sprintf("Not enough bytes. Max: %d, Offset: %d, Actual: %d", m, o, a)}
	}
	//Unicode string so each element is 2 bytes
	//move position based on the offset
	if o > 0 {
		*p += int(o * 2)
	}
	s := make([]rune, a, a)
	for i := 0; i < len(s); i++ {
		s[i] = rune(Read_uint16(b, p, e))
	}
	ensureAlignment(p, 4)
	return string(s), nil
}

func Read_UniDimensionalConformantArrayHeader(b *[]byte, p *int, e *binary.ByteOrder) int {
	return int(Read_uint32(b, p, e))
}

func ensureAlignment(p *int, byteSize int) {
	if byteSize > 0 {
		if s := *p % byteSize; s != 0 {
			*p += byteSize - s
		}
	}
}
