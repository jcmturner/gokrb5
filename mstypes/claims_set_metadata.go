package mstypes

import (
	"encoding/binary"
	"github.com/jcmturner/gokrb5/ndr"
)

// ClaimsSetMetadata implements https://msdn.microsoft.com/en-us/library/hh554073.aspx
type ClaimsSetMetadata struct {
	ULClaimsSetSize             uint32
	ClaimsSet                   []byte
	USCompressionFormat         uint32 // Enum see constants below for options
	ULUncompressedClaimsSetSize uint32
	USReservedType              uint16
	ULReservedFieldSize         uint32
	ReservedField               []byte
}

const (
	CompressionFormatNone       = 0
	CompressionFormatLZNT1      = 2
	CompressionFormatXPress     = 3
	CompressionFormatXPressHuff = 4
)

// Read_ClaimsSetMetadata reads a ClaimsSetMetadata from the bytes slice.
func ReadClaimsSetMetadata(b *[]byte, p *int, e *binary.ByteOrder) ClaimsSetMetadata {
	var c ClaimsSetMetadata
	c.ULClaimsSetSize = ndr.Read_uint32(b, p, e)
	c.ClaimsSet = ndr.Read_bytes(b, p, int(c.ULClaimsSetSize), e)
	c.USCompressionFormat = ndr.Read_uint32(b, p, e)
	c.ULUncompressedClaimsSetSize = ndr.Read_uint32(b, p, e)
	c.USReservedType = ndr.Read_uint16(b, p, e)
	c.ULReservedFieldSize = ndr.Read_uint32(b, p, e)
	c.ReservedField = ndr.Read_bytes(b, p, int(c.ULReservedFieldSize), e)
	return c
}
