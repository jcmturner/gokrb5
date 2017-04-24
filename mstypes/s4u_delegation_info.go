package mstypes

import (
	"encoding/binary"
	"github.com/jcmturner/gokrb5/ndr"
)

// https://msdn.microsoft.com/en-us/library/cc237944.aspx
type S4U_DelegationInfo struct {
	S4U2proxyTarget      RPC_UnicodeString // The name of the principal to whom the application can forward the ticket.
	TransitedListSize    uint32
	S4UTransitedServices []RPC_UnicodeString // List of all services that have been delegated through by this client and subsequent services or servers.. Size is value of TransitedListSize
}

func Read_S4U_DelegationInfo(b []byte, p *int, e *binary.ByteOrder) S4U_DelegationInfo {
	pt, _ := Read_RPC_UnicodeString(b, p, e)
	s := ndr.Read_uint32(b, p, e)
	ts := make([]RPC_UnicodeString, s, s)
	for i := range ts {
		ts[i], _ = Read_RPC_UnicodeString(b, p, e)
	}
	return S4U_DelegationInfo{
		S4U2proxyTarget:      pt,
		TransitedListSize:    s,
		S4UTransitedServices: ts,
	}
}
