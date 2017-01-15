package types

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.2.1

import "encoding/asn1"

type KerberosString []byte

type krbStr struct {
	Str string `asn1:"ia5"`
}

func ConvertToKerberosString(s string) (KerberosString, error) {
	val := krbStr{Str: s}
	return asn1.Marshal(val)
}
