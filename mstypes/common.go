// Microsoft types for Privilege Attribute Certificate (PAC): https://msdn.microsoft.com/en-us/library/cc237928.aspx
package mstypes

// A BYTE is an 8-bit unsigned value that corresponds to a single octet in a network protocol.
type Byte uint8

// A ULONG is a 32-bit unsigned integer (range: 0 through 4294967295 decimal).
// Because a ULONG is unsigned, its first bit (Most Significant Bit (MSB)) is not reserved for signing.
type ULong uint32

// A ULONG64 is a 64-bit unsigned integer (range: 0 through 18446744073709551615 decimal).
// Because a ULONG64 is unsigned, its first bit (Most Significant Bit (MSB)) is not reserved for signing.
type ULong64 uint64

// A USHORT is a 16-bit unsigned integer (range: 0 through 65535 decimal).
// Because a USHORT is unsigned, its first bit (Most Significant Bit (MSB)) is not reserved for signing.
type UShort uint16

// A UCHAR is an 8-bit integer with the range: 0 through 255 decimal.
// Because a UCHAR is unsigned, its first bit (Most Significant Bit (MSB)) is not reserved for signing.
type UChar uint8

// A WCHAR is a 16-bit Unicode character.
type WChar uint16
