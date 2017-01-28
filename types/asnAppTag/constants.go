package asnAppTag

const (
	Ticket         = 1
	Authenticator  = 2
	EncTicketPart  = 3
	ASREQ          = 10
	TGSREQ         = 12
	ASREP          = 11
	TGSREP         = 13
	APREQ          = 14
	APREP          = 15
	KRBSafe        = 20
	KRBPriv        = 21
	KRBCred        = 22
	EncASRepPart   = 25
	EncTGSRepPart  = 26
	EncAPRepPart   = 27
	EncKrbPrivPart = 28
	EncKrbCredPart = 29
	KRBError       = 30
)
// The Marshal method of golang's asn1 package does not enable you to configure to wrap the output in an application tag.
// This method adds that wrapping tag
func AddASNAppTag(b []byte, tag int) []byte {
	// The ASN1 wrapping consists of 2 bytes:
	// 1st byte -> Identifier Octet - Application Tag
	// 2nd byte -> The length (this will be the size indicated in the input bytes + 2 for the additional bytes we add here.
	// Application Tag:
	//| Byte:       | 8                            | 7                          | 6                                         | 5 | 4 | 3 | 2 | 1             |
	//| Value:      | 0                            | 1                          | 1                                         | From the RFC spec 4120        |
	//| Explanation | Defined by the ASN1 encoding rules for an application tag | A value of 1 indicates a constructed type | The ASN Application tag value |
	// Therefore the value of the byte is an integer = ( Application tag value + 96 )
	b = append([]byte{byte(96 + tag), byte(b[1] + 2)}, b...)
	return b
}
//TODO review if we want to consolidate with the MsgTypes in the dictionary
