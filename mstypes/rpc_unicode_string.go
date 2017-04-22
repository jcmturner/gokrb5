package mstypes

// https://msdn.microsoft.com/en-us/library/cc230365.aspx
type RPC_UnicodeString struct {
	Length        UShort // The length, in bytes, of the string pointed to by the Buffer member, not including the terminating null character if any. The length MUST be a multiple of 2. The length SHOULD equal the entire size of the Buffer, in which case there is no terminating null character. Any method that accesses this structure MUST use the Length specified instead of relying on the presence or absence of a null character.
	MaximumLength UShort // The maximum size, in bytes, of the string pointed to by Buffer. The size MUST be a multiple of 2. If not, the size MUST be decremented by 1 prior to use. This value MUST not be less than Length.
	Buffer        WChar  // A pointer to a string buffer. If MaximumLength is greater than zero, the buffer MUST contain a non-null value.
}
