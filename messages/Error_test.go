package messages


/*
KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
	pvno            [0] INTEGER (5),
	msg-type        [1] INTEGER (30),
	ctime           [2] KerberosTime OPTIONAL,
	cusec           [3] Microseconds OPTIONAL,
	stime           [4] KerberosTime,
	susec           [5] Microseconds,
	error-code      [6] Int32,
	crealm          [7] Realm OPTIONAL,
	cname           [8] PrincipalName OPTIONAL,
	realm           [9] Realm -- service realm --,
	sname           [10] PrincipalName -- service name --,
	e-text          [11] KerberosString OPTIONAL,
	e-data          [12] OCTET STRING OPTIONAL
}
*/

//encode_krb5_error
//encode_krb5_error(optionalsNULL)