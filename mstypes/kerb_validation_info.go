package mstypes

// https://msdn.microsoft.com/en-us/library/cc237948.aspx
type KerbValidationInfo struct {
	LogOnTime              FileTime
	LogOffTime             FileTime
	KickOffTime            FileTime
	PasswordLastSet        FileTime
	PasswordCanChange      FileTime
	PasswordMustChange     FileTime
	EffectiveName          RPC_UnicodeString
	FullName               RPC_UnicodeString
	LogonScript            RPC_UnicodeString
	ProfilePath            RPC_UnicodeString
	HomeDirectory          RPC_UnicodeString
	HomeDirectoryDrive     RPC_UnicodeString
	LogonCount             UShort
	BadPasswordCount       UShort
	UserID                 ULong
	PrimaryGroupID         ULong
	GroupCount             ULong
	GroupIDs               []GroupMembership //TODO ptr - size of the slice is GroupCount value
	UserFlags              ULong
	UserSessionKey         UserSessionKey
	LogonServer            RPC_UnicodeString
	LogonDomainName        RPC_UnicodeString
	LogonDomainID          RPC_SID
	Reserved1              ULong
	UserAccountControl     ULong
	Reserved3              ULong
	SIDCount               ULong
	ExtraSIDs              KerbSidAndAttributes //TODO ptr
	ResourceGroupDomainSID RPC_SID
	ResourceGroupCount     ULong
	ResourceGroupIDs       []GroupMembership //TODO ptr - size of the slice is ResourceGroupCount value
	//SubAuthStatus          ULong
	//LastSuccessfullILogon   FileTime
	//LastFailedILogon       FileTime
	//FailedILogonCount      ULong
}

const (
	USERFLAG_GUEST                                    = 31 // Authentication was done via the GUEST account; no password was used.
	USERFLAG_NO_ENCRYPTION_AVAILABLE                  = 30 // No encryption is available.
	USERFLAG_LAN_MANAGER_KEY                          = 28 // LAN Manager key was used for authentication.
	USERFLAG_SUB_AUTH                                 = 25 // Sub-authentication used; session key came from the sub-authentication package.
	USERFLAG_EXTRA_SIDS                               = 26 // Indicates that the ExtraSids field is populated and contains additional SIDs.
	USERFLAG_MACHINE_ACCOUNT                          = 24 // Indicates that the account is a machine account.
	USERFLAG_DC_NTLM2                                 = 23 // Indicates that the domain controller understands NTLMv2.
	USERFLAG_RESOURCE_GROUPIDS                        = 22 // Indicates that the ResourceGroupIds field is populated.
	USERFLAG_PROFILEPATH                              = 21 // Indicates that ProfilePath is populated.
	USERFLAG_NTLM2_NTCHALLENGERESP                    = 20 // The NTLMv2 response from the NtChallengeResponseFields ([MS-NLMP] section 2.2.1.3) was used for authentication and session key generation.
	USERFLAG_LM2_LMCHALLENGERESP                      = 19 // The LMv2 response from the LmChallengeResponseFields ([MS-NLMP] section 2.2.1.3) was used for authentication and session key generation.
	USERFLAG_AUTH_LMCHALLENGERESP_KEY_NTCHALLENGERESP = 18 // The LMv2 response from the LmChallengeResponseFields ([MS-NLMP] section 2.2.1.3) was used for authentication and the NTLMv2 response from the NtChallengeResponseFields ([MS-NLMP] section 2.2.1.3) was used session key generation.
)
