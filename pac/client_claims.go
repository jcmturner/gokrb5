package pac

import (
	"fmt"

	"gopkg.in/jcmturner/gokrb5.v5/mstypes"
	"gopkg.in/jcmturner/gokrb5.v5/ndr"
)

// Claims reference: https://msdn.microsoft.com/en-us/library/hh553895.aspx

// ClientClaimsInfo implements https://msdn.microsoft.com/en-us/library/hh536365.aspx
type ClientClaimsInfo struct {
	Claims mstypes.ClaimsSetMetadata
}

// Unmarshal bytes into the ClientClaimsInfo struct
func (k *ClientClaimsInfo) Unmarshal(b []byte) error {
	//var i int
	//var le binary.ByteOrder = binary.LittleEndian
	//for i < len(b) {
	//	p := i
	//	fmt.Fprintf(os.Stderr, "%d %s\n", i, ndr.ReadUTF16String(len(b[i:]), &b, &p, &le))
	//	i ++
	//}

	ch, _, p, err := ndr.ReadHeaders(&b)
	if err != nil {
		return fmt.Errorf("error parsing byte stream headers of CLIENT_CLAIMS_INFO: %v", err)
	}
	e := &ch.Endianness

	//The next 4 bytes are an RPC unique pointer referent. We just skip these
	p += 4

	k.Claims = mstypes.ReadClaimsSetMetadata(&b, &p, e)
	//This is a ClaimsBlob https://msdn.microsoft.com/en-us/library/hh554119.aspx
	//cb := mstypes.ReadClaimsBlob(&b, &p, e)
	//fmt.Fprintf(os.Stderr, "%+v\n%d\n%d %v\n", cb, len(cb.EncodedBlob), p, b[p:])
	//if cb.ULBlobSizeinBytes > 0 {
	//	var i int
	//	//i=24
	//	//i = 36
	//	k.Claims = mstypes.ReadClaimsSetMetadata(&cb.EncodedBlob, &i, e)
	//	if err != nil {
	//		return err
	//	}
	//	p += i
	//}
	//fmt.Fprintf(os.Stderr, "%d %+v\n", p, b[p:])

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
