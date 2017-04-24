package mstypes

import (
	"encoding/binary"
	"github.com/jcmturner/gokrb5/ndr"
)

// https://msdn.microsoft.com/en-us/library/dd240468.aspx
type UPN_DNSInfo struct {
	UPNLength           uint16 // An unsigned 16-bit integer in little-endian format that specifies the length, in bytes, of the UPN field.
	UPNOffset           uint16 // An unsigned 16-bit integer in little-endian format that contains the offset to the beginning of the buffer, in bytes, from the beginning of the UPN_DNS_INFO structure.
	DNSDomainNameLength uint16
	DNSDomainNameOffset uint16
	Flags               uint32
}

const (
	UPN_NO_UPN_ATTR = 31 // The user account object does not have the userPrincipalName attribute ([MS-ADA3] section 2.349) set. A UPN constructed by concatenating the user name with the DNS domain name of the account domain is provided.
)

func Read_UPN_DNSInfo(b []byte, p *int, e *binary.ByteOrder) UPN_DNSInfo {
	l := ndr.Read_uint16(b, p, e)
	o := ndr.Read_uint16(b, p, e)
	dnsl := ndr.Read_uint16(b, p, e)
	dnso := ndr.Read_uint16(b, p, e)
	f := ndr.Read_uint32(b, p, e)
	return UPN_DNSInfo{
		UPNLength:           l,
		UPNOffset:           o,
		DNSDomainNameLength: dnsl,
		DNSDomainNameOffset: dnso,
		Flags:               f,
	}
}
