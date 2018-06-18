package pac

import (
	"encoding/binary"

	"gopkg.in/jcmturner/gokrb5.v5/mstypes"
	"gopkg.in/jcmturner/gokrb5.v5/ndr"
)

// ClientClaimsInfo implements https://msdn.microsoft.com/en-us/library/hh536365.aspx
type ClientClaimsInfo struct {
	Claims mstypes.ClaimsSetMetadata
}

// Unmarshal bytes into the ClientClaimsInfo struct
func (k *ClientClaimsInfo) Unmarshal(b []byte) error {
	var p int
	var e binary.ByteOrder = binary.LittleEndian

	//This is a ClaimsBlob https://msdn.microsoft.com/en-us/library/hh554119.aspx
	cb := mstypes.ReadClaimsBlob(&b, &p, &e)

	if cb.ULBlobSizeinBytes > 0 {
		var i int
		k.Claims = mstypes.ReadClaimsSetMetadata(&cb.EncodedBlob, &i, &e)
		p = i
	}

	//Check that there is only zero padding left
	if len(b) >= p {
		for _, v := range b[p:] {
			if v != 0 {
				return ndr.Malformed{EText: "Non-zero padding left over at end of data stream"}
			}
		}
	}

	return nil
}
