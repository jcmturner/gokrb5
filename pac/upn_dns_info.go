package pac

import (
	"fmt"
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

func (k *UPN_DNSInfo) Unmarshal(b []byte) error {
	ch, _, p, err := ndr.ReadHeaders(&b)
	if err != nil {
		return fmt.Errorf("Error parsing byte stream headers: %v", err)
	}
	e := &ch.Endianness

	//The next 4 bytes are an RPC unique pointer referent. We just skip these
	p += 4

	k.UPNLength = ndr.Read_uint16(&b, &p, e)
	k.UPNOffset = ndr.Read_uint16(&b, &p, e)
	k.DNSDomainNameLength = ndr.Read_uint16(&b, &p, e)
	k.DNSDomainNameOffset = ndr.Read_uint16(&b, &p, e)
	k.Flags = ndr.Read_uint32(&b, &p, e)

	//Check that there is only zero padding left
	for _, v := range b[p:] {
		if v != 0 {
			return ndr.NDRMalformed{EText: "Non-zero padding left over at end of data stream"}
		}
	}

	return nil
}
