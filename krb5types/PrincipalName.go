package krb5types

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.2.2

type PrincipalName struct {
	NameType int `asn1:"explicit,tag:0"`
	NameString []string `asn1:"explicit,tag:1,ia5"`
}
