package pac

import (
	"fmt"
	"github.com/jcmturner/gokrb5/mstypes"
	"github.com/jcmturner/gokrb5/ndr"
)

// https://msdn.microsoft.com/en-us/library/hh554226.aspx
type PAC_DeviceClaimsInfo struct {
	Claims mstypes.ClaimsSetMetadata
}

func (k *PAC_DeviceClaimsInfo) Unmarshal(b []byte) error {
	ch, _, p, err := ndr.ReadHeaders(&b)
	if err != nil {
		return fmt.Errorf("Error parsing byte stream headers: %v", err)
	}
	e := &ch.Endianness

	//The next 4 bytes are an RPC unique pointer referent. We just skip these
	p += 4

	k.Claims = mstypes.Read_ClaimsSetMetadata(&b, &p, e)

	//Check that there is only zero padding left
	if len(b) >= p {
		for _, v := range b[p:] {
			if v != 0 {
				return ndr.NDRMalformed{EText: "Non-zero padding left over at end of data stream"}
			}
		}
	}

	return nil
}
