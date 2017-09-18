package rfc4757

import "encoding/binary"

func MessageTypeBytes(T uint32) []byte {
	// Translate usage numbers to the Microsoft T numbers
	switch T {
	case 3:
		T = 8
	case 9:
		T = 8
	case 23:
		T = 13
	}
	// Now convert to bytes
	tb := make([]byte, 4) // We force an int32 input so we can't go over 4 bytes
	binary.PutUvarint(tb, uint64(T))
	return tb
}
