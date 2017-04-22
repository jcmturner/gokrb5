package ndr

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
	Version             uint8
	Endianness          binary.ByteOrder
	CharacterEncoding   int
	FloatRepresentation uint8
	HeaderLength        uint8
	Filler              []byte
}

type PrivateHeader struct {
	ObjectBufferLength uint32
	Filler             []byte
}

func getCommonHeader(b []byte) (CommonHeader, []byte, error) {
	//The first 8 bytes comprise the Common RPC Header for type marshalling.
	if len(b) < COMMON_HEADER_BYTES {
		return NDRMalformed{EText: "Not enough bytes."}
	}
	if b[0] != PROTOCOL_VERSION {
		return NDRMalformed{EText: fmt.Sprintf("Stream does not indicate a RPC Type serialization of version %v", PROTOCOL_VERSION)}
	}
	endian := int(b[1] >> 4 & 0xF)
	if endian != 0 || endian != 1 {
		return NDRMalformed{EText: "Common header does not indicate a valid endianness"}
	}
	charEncoding := uint8(b[1] & 0xF)
	if charEncoding != 0 || charEncoding != 1 {
		return NDRMalformed{EText: "Common header does not indicate a valid charater encoding"}
	}
	if uint8(b[3]) != COMMON_HEADER_BYTES {
		return NDRMalformed{EText: "Common header does not indicate a valid length"}
	}
	var bo binary.ByteOrder
	switch endian {
	case LITTLE_ENDIAN:
		bo = binary.LittleEndian
	case BIG_ENDIAN:
		bo = binary.BigEndian
	}

	return CommonHeader{
		Version:             uint8(b[0]),
		Endianness:          bo,
		CharacterEncoding:   charEncoding,
		FloatRepresentation: uint8(b[2]),
		HeaderLength:        uint8(b[3]),
		Filler:              b[4:8],
	}, b[8:], nil
}

func getPrivateHeader(b []byte, bo binary.ByteOrder) (PrivateHeader, []byte, error) {
	//The next 8 bytes comprise the RPC type marshalling private header for constructed types.
	if len(b) < (PRIVATE_HEADER_BYTES) {
		return NDRMalformed{EText: "Not enough bytes."}
	}
	var l uint32
	buf := bytes.NewBuffer(b[1:4])
	binary.Read(buf, bo, &l)
	if l%8 != 0 {
		return NDRMalformed{EText: "Object buffer length not a multiple of 8"}
	}

	return PrivateHeader{
		ObjectBufferLength: l,
		Filler:             b[4:8],
	}, b[8:], nil
}

// Read bytes representing an eight bit integer.
func read_uint8(b []byte, p *int, e *binary.ByteOrder) (i uint8) {
	buf := bytes.NewBuffer(b[*p : *p+1])
	binary.Read(buf, *e, &i)
	*p += 1
	return
}

// Read bytes representing a sixteen bit integer.
func read_uint16(b []byte, p *int, e *binary.ByteOrder) (i uint16) {
	buf := bytes.NewBuffer(b[*p : *p+2])
	binary.Read(buf, *e, &i)
	*p += 2
	return
}

// Read bytes representing a thirty two bit integer.
func read_uint32(b []byte, p *int, e *binary.ByteOrder) (i uint32) {
	buf := bytes.NewBuffer(b[*p : *p+4])
	binary.Read(buf, *e, &i)
	*p += 4
	return
}

func read_Bytes(b []byte, p *int, s int, e *binary.ByteOrder) []byte {
	buf := bytes.NewBuffer(b[*p : *p+s])
	r := make([]byte, s)
	binary.Read(buf, *e, &r)
	*p += s
	return r
}
