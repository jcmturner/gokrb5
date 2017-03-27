package GSSAPI

import "github.com/jcmturner/asn1"

const (
	TOK_ID_KRB_AP_REQ = "0100"
	TOK_ID_KRB_AP_REP = "0200"
	TOK_ID_KRB_ERROR  = "0300"
)

// Is wrapped in application tag with value 0
type KRB5MechToken struct {
	OID    asn1.ObjectIdentifier
	TOK_ID []byte
}
