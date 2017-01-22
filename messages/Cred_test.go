package messages

/*
KRB-CRED        ::= [APPLICATION 22] SEQUENCE {
	pvno            [0] INTEGER (5),
	msg-type        [1] INTEGER (22),
	tickets         [2] SEQUENCE OF Ticket,
	enc-part        [3] EncryptedData -- EncKrbCredPart
}

EncKrbCredPart  ::= [APPLICATION 29] SEQUENCE {
	ticket-info     [0] SEQUENCE OF KrbCredInfo,
	nonce           [1] UInt32 OPTIONAL,
	timestamp       [2] KerberosTime OPTIONAL,
	usec            [3] Microseconds OPTIONAL,
	s-address       [4] HostAddress OPTIONAL,
	r-address       [5] HostAddress OPTIONAL
}

KrbCredInfo     ::= SEQUENCE {
	key             [0] EncryptionKey,
	prealm          [1] Realm OPTIONAL,
	pname           [2] PrincipalName OPTIONAL,
	flags           [3] TicketFlags OPTIONAL,
	authtime        [4] KerberosTime OPTIONAL,
	starttime       [5] KerberosTime OPTIONAL,
	endtime         [6] KerberosTime OPTIONAL,
	renew-till      [7] KerberosTime OPTIONAL,
	srealm          [8] Realm OPTIONAL,
	sname           [9] PrincipalName OPTIONAL,
	caddr           [10] HostAddresses OPTIONAL
}
*/

//encode_krb5_cred
//encode_krb5_enc_cred_part
//encode_krb5_enc_cred_part(optionalsNULL)