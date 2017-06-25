package mstypes

import (
	"encoding/binary"
	"github.com/jcmturner/gokrb5/ndr"
)

const (
	SE_GROUP_MANDATORY          = 31
	SE_GROUP_ENABLED_BY_DEFAULT = 30
	SE_GROUP_ENABLED            = 29
	SE_GROUP_OWNER              = 28
	SE_GROUP_RESOURCE           = 2
	//All other bits MUST be set to zero and MUST be  ignored on receipt.
)

// KerbSidAndAttributes implements https://msdn.microsoft.com/en-us/library/cc237947.aspx
type KerbSidAndAttributes struct {
	SID        RPC_SID // A pointer to an RPC_SID structure.
	Attributes uint32
}

// Read_KerbSidAndAttributes reads a KerbSidAndAttribute from the bytes slice.
func Read_KerbSidAndAttributes(b *[]byte, p *int, e *binary.ByteOrder) (KerbSidAndAttributes, error) {
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
