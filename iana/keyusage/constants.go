// Key usage assigned numbers.
package keyusage

const (
	//Key usage numbers
	AS_REQ_PA_ENC_TIMESTAMP                        = 1
	KDC_REP_TICKET                                 = 2
	AS_REP_ENCPART                                 = 3
	TGS_REQ_KDC_REQ_BODY_AUTHDATA_SESSION_KEY      = 4
	TGS_REQ_KDC_REQ_BODY_AUTHDATA_SUB_KEY          = 5
	TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM = 6
	TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR        = 7
	TGS_REP_ENCPART_SESSION_KEY                    = 8
	TGS_REP_ENCPART_AUTHENTICATOR_SUB_KEY          = 9
	AP_REQ_AUTHENTICATOR_CHKSUM                    = 10
	AP_REQ_AUTHENTICATOR                           = 11
	AP_REP_ENCPART                                 = 12
	KRB_PRIV_ENCPART                               = 13
	KRB_CRED_ENCPART                               = 14
	KRB_SAFE_CHKSUM                                = 15
	//16-18.  Reserved for future use in Kerberos and related protocols.
	AD_KDC_ISSUED_CHKSUM = 19
	//20-21.  Reserved for future use in Kerberos and related protocols.
	GSSAPI_ACCEPTOR_SEAL  = 22
	GSSAPI_ACCEPTOR_SIGN  = 23
	GSSAPI_INITIATOR_SEAL = 24
	GSSAPI_INITIATOR_SIGN = 25
	KEY_USAGE_AS_REQ      = 56
	//26-511.  Reserved for future use in Kerberos and related protocols.
	//512-1023.  Reserved for uses internal to a Kerberos implementation.
	//1024.  Encryption for application use in protocols that do not specify key usage values
	//1025.  Checksums for application use in protocols that do not specify key usage values
	//1026-2047.  Reserved for application use.
)
