package mstypes

import (
	"encoding/binary"
	"github.com/jcmturner/gokrb5/ndr"
)

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

// https://msdn.microsoft.com/en-us/library/cc237948.aspx
// The KERB_VALIDATION_INFO structure defines the user's logon and authorization information
// provided by the DC. The KERB_VALIDATION_INFO structure is a subset of the
// NETLOGON_VALIDATION_SAM_INFO4 structure ([MS-NRPC] section 2.2.1.4.13).
// It is a subset due to historical reasons and to the use of the common Active Directory to generate this information.
// The KERB_VALIDATION_INFO structure is marshaled by RPC [MS-RPCE].
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
	LogonCount             uint16
	BadPasswordCount       uint16
	UserID                 uint32
	PrimaryGroupID         uint32
	GroupCount             uint32
	GroupIDs               []GroupMembership
	UserFlags              uint32
	UserSessionKey         UserSessionKey
	LogonServer            RPC_UnicodeString
	LogonDomainName        RPC_UnicodeString
	LogonDomainID          RPC_SID
	Reserved1              []uint32 // Has 2 elements
	UserAccountControl     uint32
	Reserved3              []uint32
	SIDCount               uint32
	ExtraSIDs              KerbSidAndAttributes
	ResourceGroupDomainSID RPC_SID
	ResourceGroupCount     uint32
	ResourceGroupIDs       []GroupMembership
	//SubAuthStatus          uint32
	//LastSuccessfullILogon   FileTime
	//LastFailedILogon       FileTime
	//FailedILogonCount      uint32
}

func (k *KerbValidationInfo) ReadFromStream(b []byte, p *int, e *binary.ByteOrder) (err error) {
	k.LogOnTime = Read_FileTime(b, p, e)
	k.LogOffTime = Read_FileTime(b, p, e)
	k.KickOffTime = Read_FileTime(b, p, e)
	k.PasswordLastSet = Read_FileTime(b, p, e)
	k.PasswordCanChange = Read_FileTime(b, p, e)
	k.PasswordMustChange = Read_FileTime(b, p, e)

	k.EffectiveName, err = Read_RPC_UnicodeString(b, p, e)
	k.FullName, err = Read_RPC_UnicodeString(b, p, e)
	k.LogonScript, err = Read_RPC_UnicodeString(b, p, e)
	k.ProfilePath, err = Read_RPC_UnicodeString(b, p, e)
	k.HomeDirectory, err = Read_RPC_UnicodeString(b, p, e)
	k.HomeDirectoryDrive, err = Read_RPC_UnicodeString(b, p, e)
	if err != nil {
		return
	}

	k.LogonCount = ndr.Read_uint16(b, p, e)
	k.BadPasswordCount = ndr.Read_uint16(b, p, e)
	k.UserID = ndr.Read_uint32(b, p, e)
	k.PrimaryGroupID = ndr.Read_uint32(b, p, e)
	k.GroupCount = ndr.Read_uint32(b, p, e)

	if k.GroupCount > 0 {
		g := make([]GroupMembership, k.GroupCount, k.GroupCount)
		for i := range g {
			if grpMemPtr := ndr.Read_uint32(b, p, e); grpMemPtr != 0 {
				g[i] = Read_GroupMembership(b, grpMemPtr, e)
			}
			k.GroupIDs = g
		}
	}

	k.UserFlags = ndr.Read_uint32(b, p, e)
	k.UserSessionKey = Read_UserSessionKey(b, p, e)

	k.LogonServer, err = Read_RPC_UnicodeString(b, p, e)
	k.LogonDomainName, err = Read_RPC_UnicodeString(b, p, e)
	if err != nil {
		return
	}

	if lDomIDPtr := ndr.Read_uint32(b, p, e); lDomIDPtr != 0 {
		k.LogonDomainID = Read_RPC_SID(b, lDomIDPtr, e)
	}

	k.Reserved1 = []uint32{
		ndr.Read_uint32(b, p, e),
		ndr.Read_uint32(b, p, e),
	}

	k.UserAccountControl = ndr.Read_uint32(b, p, e)

	r := make([]uint32, 7, 7)
	for i := range r {
		r[i] = ndr.Read_uint32(b, p, e)
	}
	k.Reserved3 = r

	k.SIDCount = ndr.Read_uint32(b, p, e)
	if k.SIDCount > 0 {
		es := make([]KerbSidAndAttributes, k.SIDCount, k.SIDCount)
		for i := range es {
			if eSIDPtr := ndr.Read_uint32(b, p, e); eSIDPtr != 0 {
				es[i] = Read_KerbSidAndAttributes(b, eSIDPtr, e)
			}
			k.ExtraSIDs = es
		}
	}

	if rGrpDomSIDPtr := ndr.Read_uint32(b, p, e); rGrpDomSIDPtr != 0 {
		k.ResourceGroupDomainSID = Read_RPC_SID(b, rGrpDomSIDPtr, e)
	}

	k.ResourceGroupCount = ndr.Read_uint32(b, p, e)
	if k.ResourceGroupCount > 0 {
		rg := make([]GroupMembership, k.ResourceGroupCount, k.ResourceGroupCount)
		for i := range rg {
			if resGrpIDPtr := ndr.Read_uint32(b, p, e); resGrpIDPtr != 0 {
				rg[i] = Read_GroupMembership(b, resGrpIDPtr, e)
			}
			k.ResourceGroupIDs = rg
		}
	}

	return nil
}
