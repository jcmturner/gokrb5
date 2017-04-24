package mstypes

import (
	"encoding/binary"
	"github.com/jcmturner/gokrb5/ndr"
)

// https://msdn.microsoft.com/en-us/library/cc237950.aspx
type PACType struct {
	CBuffers uint32
	Version  uint32
	Buffers  []PACInfoBuffer // Size 1
}

func Read_PACType(b []byte, p *int, e *binary.ByteOrder) PACType {
	c := ndr.Read_uint32(b, p, e)
	v := ndr.Read_uint32(b, p, e)
	return PACType{
		CBuffers: c,
		Version:  v,
		Buffers:  []PACInfoBuffer{Read_PACInfoBuffer(b, p, e)},
	}
}
