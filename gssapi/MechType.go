package gssapi

import "github.com/jcmturner/asn1"

// MechTypeOID_Krb5 is the MechType OID for Kerberos 5
var MechTypeOID_Krb5 = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}

// MechTypeOID_MSLegacyKrb5 is the MechType OID for MS legacy Kerberos 5
var MechTypeOID_MSLegacyKrb5 = asn1.ObjectIdentifier{1, 2, 840, 48018, 1, 2, 2}
