package pac

import (
	"fmt"
	"github.com/jcmturner/gokrb5/mstypes"
	"github.com/jcmturner/gokrb5/ndr"
)

// S4U_DelegationInfo implements https://msdn.microsoft.com/en-us/library/cc237944.aspx
type S4UDelegationInfo struct {
	S4U2proxyTarget      mstypes.RPC_UnicodeString // The name of the principal to whom the application can forward the ticket.
	TransitedListSize    uint32
	S4UTransitedServices []mstypes.RPC_UnicodeString // List of all services that have been delegated through by this client and subsequent services or servers.. Size is value of TransitedListSize
}

// Unmarshal bytes into the S4U_DelegationInfo struct
func (k *S4UDelegationInfo) Unmarshal(b []byte) error {
	ch, _, p, err := ndr.ReadHeaders(&b)
	if err != nil {
		return fmt.Errorf("Error parsing byte stream headers: %v", err)
	}
	e := &ch.Endianness

	//The next 4 bytes are an RPC unique pointer referent. We just skip these
	p += 4

	k.S4U2proxyTarget, err = mstypes.Read_RPC_UnicodeString(&b, &p, e)
	if err != nil {
		return err
	}
	k.TransitedListSize = ndr.Read_uint32(&b, &p, e)
	if k.TransitedListSize > 0 {
		ts := make([]mstypes.RPC_UnicodeString, k.TransitedListSize, k.TransitedListSize)
		for i := range ts {
			ts[i], err = mstypes.Read_RPC_UnicodeString(&b, &p, e)
			if err != nil {
				return err
			}
		}
		for i := range ts {
			ts[i].UnmarshalString(&b, &p, e)
		}
		k.S4UTransitedServices = ts
	}

	//Check that there is only zero padding left
	for _, v := range b[p:] {
		if v != 0 {
			return ndr.Malformed{EText: "Non-zero padding left over at end of data stream"}
		}
	}

	return nil
}
