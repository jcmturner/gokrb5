package messages

/*
KRB-SAFE        ::= [APPLICATION 20] SEQUENCE {
	pvno            [0] INTEGER (5),
	msg-type        [1] INTEGER (20),
	safe-body       [2] KRB-SAFE-BODY,
	cksum           [3] Checksum
}

KRB-SAFE-BODY   ::= SEQUENCE {
	user-data       [0] OCTET STRING,
	timestamp       [1] KerberosTime OPTIONAL,
	usec            [2] Microseconds OPTIONAL,
	seq-number      [3] UInt32 OPTIONAL,
	s-address       [4] HostAddress,
	r-address       [5] HostAddress OPTIONAL
}
*/

//encode_krb5_safe
//encode_krb5_safe(optionalsNULL)