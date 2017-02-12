package messages

const (
	//Key usage numbers
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

	//Message IDs
	KRB_AS_REQ     = 10 //Request for initial authentication
	KRB_AS_REP     = 11 //Response to KRB_AS_REQ request
	KRB_TGS_REQ    = 12 //Request for authentication based on TGT
	KRB_TGS_REP    = 13 //Response to KRB_TGS_REQ request
	KRB_AP_REQ     = 14 //Application request to server
	KRB_AP_REP     = 15 //Response to KRB_AP_REQ_MUTUAL
	KRB_RESERVED16 = 16 //Reserved for user-to-user krb_tgt_request
	KRB_RESERVED17 = 17 //Reserved for user-to-user krb_tgt_reply
	KRB_SAFE       = 20 // Safe (checksummed) application message
	KRB_PRIV       = 21 // Private (encrypted) application message
	KRB_CRED       = 22 //Private (encrypted) message to forward credentials
	KRB_ERROR      = 30 //Error response

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

	//Error codes
	KDC_ERR_NONE                          = 0  //No error
	KDC_ERR_NAME_EXP                      = 1  //Client's entry in database has expired
	KDC_ERR_SERVICE_EXP                   = 2  //Server's entry in database has expired
	KDC_ERR_BAD_PVNO                      = 3  //Requested protocol version number not supported
	KDC_ERR_C_OLD_MAST_KVNO               = 4  //Client's key encrypted in old master key
	KDC_ERR_S_OLD_MAST_KVNO               = 5  //Server's key encrypted in old master key
	KDC_ERR_C_PRINCIPAL_UNKNOWN           = 6  //Client not found in Kerberos database
	KDC_ERR_S_PRINCIPAL_UNKNOWN           = 7  //Server not found in Kerberos database
	KDC_ERR_PRINCIPAL_NOT_UNIQUE          = 8  //Multiple principal entries in database
	KDC_ERR_NULL_KEY                      = 9  //The client or server has a null key
	KDC_ERR_CANNOT_POSTDATE               = 10 //Ticket not eligible for  postdating
	KDC_ERR_NEVER_VALID                   = 11 //Requested starttime is later than end time
	KDC_ERR_POLICY                        = 12 //KDC policy rejects request
	KDC_ERR_BADOPTION                     = 13 //KDC cannot accommodate requested option
	KDC_ERR_ETYPE_NOSUPP                  = 14 //KDC has no support for  encryption type
	KDC_ERR_SUMTYPE_NOSUPP                = 15 //KDC has no support for  checksum type
	KDC_ERR_PADATA_TYPE_NOSUPP            = 16 //KDC has no support for  padata type
	KDC_ERR_TRTYPE_NOSUPP                 = 17 //KDC has no support for  transited type
	KDC_ERR_CLIENT_REVOKED                = 18 //Clients credentials have been revoked
	KDC_ERR_SERVICE_REVOKED               = 19 //Credentials for server have been revoked
	KDC_ERR_TGT_REVOKED                   = 20 //TGT has been revoked
	KDC_ERR_CLIENT_NOTYET                 = 21 //Client not yet valid; try again later
	KDC_ERR_SERVICE_NOTYET                = 22 //Server not yet valid; try again later
	KDC_ERR_KEY_EXPIRED                   = 23 //Password has expired; change password to reset
	KDC_ERR_PREAUTH_FAILED                = 24 //Pre-authentication information was invalid
	KDC_ERR_PREAUTH_REQUIRED              = 25 //Additional pre- authentication required
	KDC_ERR_SERVER_NOMATCH                = 26 //Requested server and ticket don't match
	KDC_ERR_MUST_USE_USER2USER            = 27 //Server principal valid for  user2user only
	KDC_ERR_PATH_NOT_ACCEPTED             = 28 //KDC Policy rejects transited path
	KDC_ERR_SVC_UNAVAILABLE               = 29 //A service is not available
	KRB_AP_ERR_BAD_INTEGRITY              = 31 //Integrity check on decrypted field failed
	KRB_AP_ERR_TKT_EXPIRED                = 32 //Ticket expired
	KRB_AP_ERR_TKT_NYV                    = 33 //Ticket not yet valid
	KRB_AP_ERR_REPEAT                     = 34 //Request is a replay
	KRB_AP_ERR_NOT_US                     = 35 //The ticket isn't for us
	KRB_AP_ERR_BADMATCH                   = 36 //Ticket and authenticator don't match
	KRB_AP_ERR_SKEW                       = 37 //Clock skew too great
	KRB_AP_ERR_BADADDR                    = 38 //Incorrect net address
	KRB_AP_ERR_BADVERSION                 = 39 //Protocol version mismatch
	KRB_AP_ERR_MSG_TYPE                   = 40 //Invalid msg type
	KRB_AP_ERR_MODIFIED                   = 41 //Message stream modified
	KRB_AP_ERR_BADORDER                   = 42 //Message out of order
	KRB_AP_ERR_BADKEYVER                  = 44 //Specified version of key is not available
	KRB_AP_ERR_NOKEY                      = 45 //Service key not available
	KRB_AP_ERR_MUT_FAIL                   = 46 //Mutual authentication failed
	KRB_AP_ERR_BADDIRECTION               = 47 //Incorrect message direction
	KRB_AP_ERR_METHOD                     = 48 //Alternative authentication method required
	KRB_AP_ERR_BADSEQ                     = 49 //Incorrect sequence number in message
	KRB_AP_ERR_INAPP_CKSUM                = 50 //Inappropriate type of checksum in message
	KRB_AP_PATH_NOT_ACCEPTED              = 51 //Policy rejects transited path
	KRB_ERR_RESPONSE_TOO_BIG              = 52 //Response too big for UDP;  retry with TCP
	KRB_ERR_GENERIC                       = 60 //Generic error (description in e-text)
	KRB_ERR_FIELD_TOOLONG                 = 61 //Field is too long for this implementation
	KDC_ERROR_CLIENT_NOT_TRUSTED          = 62 //Reserved for PKINIT
	KDC_ERROR_KDC_NOT_TRUSTED             = 63 //Reserved for PKINIT
	KDC_ERROR_INVALID_SIG                 = 64 //Reserved for PKINIT
	KDC_ERR_KEY_TOO_WEAK                  = 65 //Reserved for PKINIT
	KDC_ERR_CERTIFICATE_MISMATCH          = 66 //Reserved for PKINIT
	KRB_AP_ERR_NO_TGT                     = 67 //No TGT available to validate USER-TO-USER
	KDC_ERR_WRONG_REALM                   = 68 //Reserved for future use
	KRB_AP_ERR_USER_TO_USER_REQUIRED      = 69 //Ticket must be for  USER-TO-USER
	KDC_ERR_CANT_VERIFY_CERTIFICATE       = 70 //Reserved for PKINIT
	KDC_ERR_INVALID_CERTIFICATE           = 71 //Reserved for PKINIT
	KDC_ERR_REVOKED_CERTIFICATE           = 72 //Reserved for PKINIT
	KDC_ERR_REVOCATION_STATUS_UNKNOWN     = 73 //Reserved for PKINIT
	KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74 //Reserved for PKINIT
	KDC_ERR_CLIENT_NAME_MISMATCH          = 75 //Reserved for PKINIT
	KDC_ERR_KDC_NAME_MISMATCH             = 76 //Reserved for PKINIT
)
