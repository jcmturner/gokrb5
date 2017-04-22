// Authenticator type assigned numbers.
package adtype

const (
	AD_IF_RELEVANT                    = 1
	AD_INTENDED_FOR_SERVER            = 2
	AD_INTENDED_FOR_APPLICATION_CLASS = 3
	AD_KDC_ISSUED                     = 4
	AD_AND_OR                         = 5
	AD_MANDATORY_TICKET_EXTENSIONS    = 6
	AD_IN_TICKET_EXTENSIONS           = 7
	AD_MANDATORY_FOR_KDC              = 8
	//Reserved values                   9-63
	OSF_DCE                    = 64
	SESAME                     = 65
	AD_OSF_DCE_PKI_CERTID      = 66
	AD_Authentication_Strength = 70
	AD_FX_Fast_Armor           = 71
	AD_FX_Fast_Used            = 72
	AD_WIN2K_PAC               = 128
	AD_ETYPE_NEGOTIATION       = 129
)
