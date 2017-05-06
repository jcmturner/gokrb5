package pac

import (
	"encoding/binary"
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
	//The PAC_CLIENT_INFO structure is a simple structure that is not NDR-encoded.
	var p int
	var e binary.ByteOrder = binary.LittleEndian

	k.ClientID = mstypes.Read_FileTime(&b, &p, &e)
	k.NameLength = ndr.Read_uint16(&b, &p, &e)
	s := make([]rune, k.NameLength, k.NameLength)
	for i := 0; i < len(s); i++ {
		s[i] = rune(ndr.Read_uint16(&b, &p, &e))
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
