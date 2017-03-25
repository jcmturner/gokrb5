package GSSAPI

import (
	"github.com/jcmturner/asn1"
)

const (
	SPNEGO_OIDHex                = "2b0601050502"       //1.3.6.1.5.5.2
	MechType_Krb5_OIDHex         = "2a864886f712010202" //1.2.840.113554.1.2.2
	MechType_MSLegacyKrb5_OIDHex = "2a864882f712010202" //1.2.840.48018.1.2.2
)

type MechType asn1.ObjectIdentifier

type MechTypeList []MechType
