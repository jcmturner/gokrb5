package types

const (
	//PA Types
	PA_TGS_REQ       = 1
	PA_ENC_TIMESTAMP = 2
	PA_PW_SALT       = 3
	PA_ETYPE_INFO    = 11
	PA_ETYPE_INFO2   = 19
	//From RFC 6113
	PA_FX_COOKIE           = 133
	PA_AUTHENTICATION_SET  = 134
	PA_AUTH_SET_SELECTED   = 135
	PA_FX_FAST             = 136
	PA_FX_ERROR            = 137
	PA_ENCRYPTED_CHALLENGE = 138
	//RFC6806 Section 11
	PA_REQ_ENC_PA_REP = 149

	//Name types
	KRB_NT_UNKNOWN        = 0  //Name type not known
	KRB_NT_PRINCIPAL      = 1  //Just the name of the principal as in DCE,  or for users
	KRB_NT_SRV_INST       = 2  //Service and other unique instance (krbtgt)
	KRB_NT_SRV_HST        = 3  //Service with host name as instance (telnet, rcommands)
	KRB_NT_SRV_XHST       = 4  //Service with host as remaining components
	KRB_NT_UID            = 5  //Unique ID
	KRB_NT_X500_PRINCIPAL = 6  //Encoded X.509 Distinguished name [RFC2253]
	KRB_NT_SMTP_NAME      = 7  //Name in form of SMTP email name (e.g., user@example.com)
	KRB_NT_ENTERPRISE     = 10 //Enterprise name; may be mapped to principal name
)
