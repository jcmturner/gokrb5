package messages

/*
KRB-PRIV        ::= [APPLICATION 21] SEQUENCE {
	pvno            [0] INTEGER (5),
	msg-type        [1] INTEGER (21),
	enc-part        [3] EncryptedData -- EncKrbPrivPart
}

EncKrbPrivPart  ::= [APPLICATION 28] SEQUENCE {
	user-data       [0] OCTET STRING,
	timestamp       [1] KerberosTime OPTIONAL,
	usec            [2] Microseconds OPTIONAL,
	seq-number      [3] UInt32 OPTIONAL,
	s-address       [4] HostAddress -- sender's addr --,
	r-address       [5] HostAddress OPTIONAL -- recip's addr
}
*/

//encode_krb5_priv
//encode_krb5_enc_priv_part
//encode_krb5_enc_priv_part(optionalsNULL)