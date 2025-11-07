package types

// Extended PA-DATA types for Kerberos extensions
// Reference: MS-KILE

import "encoding/asn1"

// KerbPaPacRequest is the PA-PAC-REQUEST structure (MS-KILE)
// This is used to request or suppress the inclusion of a PAC in the ticket
type KerbPaPacRequest struct {
	IncludePAC bool `asn1:"explicit,tag:0"`
}

// Marshal marshals KerbPaPacRequest
func (k KerbPaPacRequest) Marshal() ([]byte, error) {
	return asn1.Marshal(k)
}

// Unmarshal unmarshals KerbPaPacRequest
func (k *KerbPaPacRequest) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, k)
	return err
}
