package asn1tools


// Get the ASN1 encoded bytes for the length 'l'
// There are two forms: short (for lengths between 0 and 127), and long definite (for lengths between 0 and 2^1008 -1).
// Short form: One octet. Bit 8 has value "0" and bits 7-1 give the length.
// Long form: Two to 127 octets. Bit 8 of first octet has value "1" and bits 7-1 give the number of additional length octets. Second and following octets give the length, base 256, most significant digit first.
func MarshalLengthBytes(l int) []byte {
	if l <= 127 {
		return []byte{byte(l)}
	}
	var b []byte
	p := 1
	for i := 1; i < 127; {
		b = append([]byte{byte((l % (p * 256)) / p)}, b...)
		p = p * 256
		l = l - l%p
		if l <= 0 {
			break
		}
	}
	return append([]byte{byte(128 + len(b))}, b...)
}

// Get the length of a slice of ASN1 encoded bytes from the ASN1 length header it contains.
func GetLengthFromASN(b []byte) int {
	if int(b[1]) <= 127 {
		return int(b[1])
	}
	// The bytes that indicate the length
	lb := b[2:2+int(b[1]) - 128]
	base := 1
	l := 0
	for i := len(lb)-1; i >= 0; i-- {
		l += int(lb[i]) * base
		base = base * 256
	}
	return l
}

// The Marshal method of golang's asn1 package does not enable you to define wrapping the output in an application tag.
// This method adds that wrapping tag.
func AddASNAppTag(b []byte, tag int) []byte {
	// The ASN1 wrapping consists of 2 bytes:
	// 1st byte -> Identifier Octet - Application Tag
	// 2nd byte -> The length (this will be the size indicated in the input bytes + 2 for the additional bytes we add here.
	// Application Tag:
	//| Byte:       | 8                            | 7                          | 6                                         | 5 | 4 | 3 | 2 | 1             |
	//| Value:      | 0                            | 1                          | 1                                         | From the RFC spec 4120        |
	//| Explanation | Defined by the ASN1 encoding rules for an application tag | A value of 1 indicates a constructed type | The ASN Application tag value |
	// Therefore the value of the byte is an integer = ( Application tag value + 96 )
	//b = append(MarshalLengthBytes(int(b[1])+2), b...)
	b = append(MarshalLengthBytes(len(b)), b...)
	b = append([]byte{byte(96 + tag)}, b...)
	return b
}
