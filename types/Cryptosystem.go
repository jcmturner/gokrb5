package types

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.2.9

// Reference: https://www.ietf.org/rfc/rfc3961.txt

type EncryptedData struct {
	EType  int    `asn1:"explicit,tag:0"`
	KVNO   int    `asn1:"explicit,optional,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

type EncryptionKey struct {
	KeyType  int    `asn1:"explicit,tag:0"`
	KeyValue []byte `asn1:"explicit,tag:1"`
}

type Checksum struct {
	CksumType int    `asn1:"explicit,tag:0"`
	Checksum  []byte `asn1:"explicit,tag:1"`
}
