package mstypes

import (
	"encoding/binary"
	"github.com/jcmturner/gokrb5/ndr"
)

const (
	SEGroupMandatory         = 31
	SSEGroupEnabledByDefault = 30
	SEGroupEnabled           = 29
	SEGroupOwner             = 28
	SEGroupResource          = 2
	//All other bits MUST be set to zero and MUST be  ignored on receipt.
)

// KerbSidAndAttributes implements https://msdn.microsoft.com/en-us/library/cc237947.aspx
type KerbSidAndAttributes struct {
	SID        RPC_SID // A pointer to an RPC_SID structure.
	Attributes uint32
}

// ReadKerbSidAndAttributes reads a KerbSidAndAttribute from the bytes slice.
func ReadKerbSidAndAttributes(b *[]byte, p *int, e *binary.ByteOrder) (KerbSidAndAttributes, error) {
	s, err := Read_RPC_SID(b, p, e)
	if err != nil {
		return KerbSidAndAttributes{}, err
	}
	a := ndr.Read_uint32(b, p, e)
	return KerbSidAndAttributes{
		SID:        s,
		Attributes: a,
	}, nil
}

// SetFlag sets a flag in a uint32 attribute value.
func SetFlag(a *uint32, i uint) {
	*a = *a | (1 << (31 - i))
}
