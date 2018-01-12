package binpacker

import "encoding/binary"

// AddUint16Perfix add 2 bytes as uint16 prefixes for bytes.
func AddUint16Perfix(bytes []byte) []byte {
	buffer := make([]byte, 2)
	binary.LittleEndian.PutUint16(buffer, uint16(len(bytes)))
	return append(buffer, bytes...)
}

// AddUint32Perfix add 4 bytes as uint32 prefixes for bytes.
func AddUint32Perfix(bytes []byte) []byte {
	buffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(buffer, uint32(len(bytes)))
	return append(buffer, bytes...)
}

// AddUint64Perfix add 8 bytes as uint64 prefixes for bytes.
func AddUint64Perfix(bytes []byte) []byte {
	buffer := make([]byte, 8)
	binary.LittleEndian.PutUint64(buffer, uint64(len(bytes)))
	return append(buffer, bytes...)
}
