package pac

import (
	"fmt"
	"github.com/jcmturner/gokrb5/mstypes"
	"github.com/jcmturner/gokrb5/ndr"
)

// https://msdn.microsoft.com/en-us/library/cc237951.aspx
type PAC_ClientInfo struct {
	ClientID   mstypes.FileTime // A FILETIME structure in little-endian format that contains the Kerberos initial ticket-granting ticket TGT authentication time
	NameLength uint16           // An unsigned 16-bit integer in little-endian format that specifies the length, in bytes, of the Name field.
	Name       string           // An array of 16-bit Unicode characters in little-endian format that contains the client's account name.
}

func (k *PAC_ClientInfo) Unmarshal(b []byte) error {
	ch, _, p, err := ndr.ReadHeaders(&b)
	if err != nil {
		return fmt.Errorf("Error parsing byte stream headers: %v", err)
	}
	e := &ch.Endianness

	//The next 4 bytes are an RPC unique pointer referent. We just skip these
	p += 4

	k.ClientID = mstypes.Read_FileTime(&b, &p, e)
	k.NameLength = ndr.Read_uint16(&b, &p, e)
	s := make([]rune, k.NameLength, k.NameLength)
	for i := 0; i < len(s); i++ {
		s[i] = rune(ndr.Read_uint16(&b, &p, e))
	}
	k.Name = string(s)

	//Check that there is only zero padding left
	for _, v := range b[p:] {
		if v != 0 {
			return ndr.NDRMalformed{EText: "Non-zero padding left over at end of data stream"}
		}
	}

	return nil
}

// TODO come back to this struct
// https://msdn.microsoft.com/en-us/library/hh536365.aspx
//type PAC_ClientClaimsInfo struct {
//	Claims ClaimsSetMetadata
//}
