package mstypes

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/jcmturner/gokrb5/ndr"
)

// https://msdn.microsoft.com/en-us/library/cc230364.aspx
type RPC_SID struct {
	Revision            uint8                      // An 8-bit unsigned integer that specifies the revision level of the SID. This value MUST be set to 0x01.
	SubAuthorityCount   uint8                      // An 8-bit unsigned integer that specifies the number of elements in the SubAuthority array. The maximum number of elements allowed is 15.
	IdentifierAuthority RPC_SIDIdentifierAuthority // An RPC_SID_IDENTIFIER_AUTHORITY structure that indicates the authority under which the SID was created. It describes the entity that created the SID. The Identifier Authority value {0,0,0,0,0,5} denotes SIDs created by the NT SID authority.
	SubAuthority        []uint32                   // A variable length array of unsigned 32-bit integers that uniquely identifies a principal relative to the IdentifierAuthority. Its length is determined by SubAuthorityCount.
}

// https://msdn.microsoft.com/en-us/library/cc230372.aspx
type RPC_SIDIdentifierAuthority struct {
	Value []byte // 6 bytes
}

func Read_RPC_SID(b *[]byte, p *int, e *binary.ByteOrder) (RPC_SID, error) {
	size := int(ndr.Read_uint32(b, p, e)) // This is part of the NDR encoding rather than the data type.
	r := ndr.Read_uint8(b, p)
	if r != uint8(1) {
		return RPC_SID{}, ndr.Malformed{EText: fmt.Sprintf("SID revision value read as %d when it must be 1", r)}
	}
	c := ndr.Read_uint8(b, p)
	a := Read_RPC_SIDIdentifierAuthority(b, p, e)
	s := make([]uint32, c, c)
	if size != len(s) {
		return RPC_SID{}, ndr.Malformed{EText: fmt.Sprintf("Number of elements (%d) within SID in the byte stream does not equal the SubAuthorityCount (%d)", size, c)}
	}
	for i := 0; i < len(s); i++ {
		s[i] = ndr.Read_uint32(b, p, e)
	}
	return RPC_SID{
		Revision:            r,
		SubAuthorityCount:   c,
		IdentifierAuthority: a,
		SubAuthority:        s,
	}, nil
}

func Read_RPC_SIDIdentifierAuthority(b *[]byte, p *int, e *binary.ByteOrder) RPC_SIDIdentifierAuthority {
	return RPC_SIDIdentifierAuthority{
		Value: ndr.Read_bytes(b, p, 6, e),
	}
}

//SID= "S-1-" IdentifierAuthority 1*SubAuthority
//IdentifierAuthority= IdentifierAuthorityDec / IdentifierAuthorityHex
//; If the identifier authority is < 2^32, the
//; identifier authority is represented as a decimal ; number
//; If the identifier authority is >= 2^32,
//; the identifier authority is represented in
//; hexadecimal
//IdentifierAuthorityDec = 1*10DIGIT
//; IdentifierAuthorityDec, top level authority of a
//; security identifier is represented as a decimal number
//IdentifierAuthorityHex = "0x" 12HEXDIG
//; IdentifierAuthorityHex, the top-level authority of a
//; security identifier is represented as a hexadecimal number
//SubAuthority= "-" 1*10DIGIT
//; Sub-Authority is always represented as a decimal number
//; No leading "0" characters are allowed when IdentifierAuthority ; or SubAuthority is represented as a decimal number
//; All hexadecimal digits must be output in string format,
//; pre-pended by "0x"
func (s *RPC_SID) ToString() string {
	var str string
	b := append(make([]byte, 2, 2), s.IdentifierAuthority.Value...)
	// For a strange reason this is read big endian: https://msdn.microsoft.com/en-us/library/dd302645.aspx
	i := binary.BigEndian.Uint64(b)
	if i >= 4294967296 {
		str = fmt.Sprintf("S-1-0x%s", hex.EncodeToString(s.IdentifierAuthority.Value))
	} else {
		str = fmt.Sprintf("S-1-%d", i)
	}
	for _, sub := range s.SubAuthority {
		str = fmt.Sprintf("%s-%d", str, sub)
	}
	return str
}
