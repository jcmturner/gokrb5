package mstypes

import (
	"encoding/binary"
	"github.com/jcmturner/gokrb5/ndr"
)

// https://msdn.microsoft.com/en-us/library/cc237951.aspx
type PAC_ClientInfo struct {
	ClientID   FileTime // A FILETIME structure in little-endian format that contains the Kerberos initial ticket-granting ticket TGT authentication time
	NameLength uint16   // An unsigned 16-bit integer in little-endian format that specifies the length, in bytes, of the Name field.
	Name       string   // An array of 16-bit Unicode characters in little-endian format that contains the client's account name.
}

func Read_PAC_ClientInfo(b []byte, p *int, e *binary.ByteOrder) PAC_ClientInfo {
	c := Read_FileTime(b, p, e)
	l := ndr.Read_uint16(b, p, e)
	s := make([]rune, l, l)
	for i := 0; i < int(l); i++ {
		s[i] = rune(ndr.Read_uint16(b, p, e))
	}
	return PAC_ClientInfo{
		ClientID:   c,
		NameLength: l,
		Name:       string(s),
	}
}

// TODO come back to this struct
// https://msdn.microsoft.com/en-us/library/hh536365.aspx
//type PAC_ClientClaimsInfo struct {
//	Claims ClaimsSetMetadata
//}
