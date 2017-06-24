package mstypes

import (
	"encoding/binary"
	"github.com/jcmturner/gokrb5/ndr"
)

// https://msdn.microsoft.com/en-us/library/cc230365.aspx
type RPC_UnicodeString struct {
	Length        uint16 // The length, in bytes, of the string pointed to by the Buffer member, not including the terminating null character if any. The length MUST be a multiple of 2. The length SHOULD equal the entire size of the Buffer, in which case there is no terminating null character. Any method that accesses this structure MUST use the Length specified instead of relying on the presence or absence of a null character.
	MaximumLength uint16 // The maximum size, in bytes, of the string pointed to by Buffer. The size MUST be a multiple of 2. If not, the size MUST be decremented by 1 prior to use. This value MUST not be less than Length.
	BufferPrt     uint32 // A pointer to a string buffer. If MaximumLength is greater than zero, the buffer MUST contain a non-null value.
	Value         string
}

// Read_RPC_UnicodeString reads a RPC_UnicodeString from the bytes slice.
func Read_RPC_UnicodeString(b *[]byte, p *int, e *binary.ByteOrder) (RPC_UnicodeString, error) {
	l := ndr.Read_uint16(b, p, e)
	ml := ndr.Read_uint16(b, p, e)
	if ml < l || l%2 != 0 || ml%2 != 0 {
		return RPC_UnicodeString{}, ndr.Malformed{EText: "Invalid data for RPC_UNICODE_STRING"}
	}
	ptr := ndr.Read_uint32(b, p, e)
	return RPC_UnicodeString{
		Length:        l,
		MaximumLength: ml,
		BufferPrt:     ptr,
	}, nil
}

// UnmarshalString populates a golang string into the RPC_UnicodeString struct.
func (s *RPC_UnicodeString) UnmarshalString(b *[]byte, p *int, e *binary.ByteOrder) (err error) {
	s.Value, err = ndr.Read_ConformantVaryingString(b, p, e)
	return
}
