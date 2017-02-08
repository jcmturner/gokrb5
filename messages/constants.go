package messages

const (
	USAGE_AS_REQ_PA_ENC_TIMESTAMP                        = 1
	USAGE_KDC_REP_TICKET                                 = 2
	USAGE_AS_REP_ENCPART                                 = 3
	USAGE_TGS_REQ_KDC_REQ_BODY_AUTHDATA_SESSION_KEY      = 4
	USAGE_TGS_REQ_KDC_REQ_BODY_AUTHDATA_SUB_KEY          = 5
	USAGE_TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM = 6
	USAGE_TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR        = 7
	USAGE_TGS_REP_ENCPART_SESSION_KEY                    = 8
	USAGE_TGS_REP_ENCPART_AUTHENTICATOR_SUB_KEY          = 9
	USAGE_AP_REQ_AUTHENTICATOR_CHKSUM                    = 10
	USAGE_AP_REQ_AUTHENTICATOR                           = 11
	USAGE_AP_REP_ENCPART                                 = 12
	USAGE_KRB_PRIV_ENCPART                               = 13
	USAGE_KRB_CRED_ENCPART                               = 14
	USAGE_KRB_SAFE_CHKSUM                                = 15
	//16-18.  Reserved for future use in Kerberos and related protocols.
	USAGE_AD_KDC_ISSUED_CHKSUM = 19
	//20-21.  Reserved for future use in Kerberos and related protocols.
	USAGE_GSSAPI_ACCEPTOR_SEAL  = 22
	USAGE_GSSAPI_ACCEPTOR_SIGN  = 23
	USAGE_GSSAPI_INITIATOR_SEAL = 24
	USAGE_GSSAPI_INITIATOR_SIGN = 25
	//26-511.  Reserved for future use in Kerberos and related protocols.
	//512-1023.  Reserved for uses internal to a Kerberos implementation.
	//1024.  Encryption for application use in protocols that do not specify key usage values
	//1025.  Checksums for application use in protocols that do not specify key usage values
	//1026-2047.  Reserved for application use.
)
