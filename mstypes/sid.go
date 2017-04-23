package mstypes

import (
	"encoding/binary"
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

func Read_RPC_SID(b []byte, p *int, e *binary.ByteOrder) RPC_SID {
	r := ndr.Read_uint8(b, p)
	c := ndr.Read_uint8(b, p)
	a := Read_RPC_SIDIdentifierAuthority(b, p, e)
	s := make([]int32, c, c)
	for i := 0; i < c; i++ {
		s[i] = ndr.Read_uint32(b, p, e)
	}
	return RPC_SID{
		Revision:            r,
		SubAuthorityCount:   c,
		IdentifierAuthority: a,
		SubAuthority:        s,
	}
}

func Read_RPC_SIDIdentifierAuthority(b []byte, p *int, e *binary.ByteOrder) RPC_SIDIdentifierAuthority {
	return RPC_SIDIdentifierAuthority{
		Value: ndr.Read_bytes(b, p, 6, e),
	}
}
