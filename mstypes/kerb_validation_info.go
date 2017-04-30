package mstypes

import (
	"errors"
	"fmt"
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
	LogOnTime               FileTime
	LogOffTime              FileTime
	KickOffTime             FileTime
	PasswordLastSet         FileTime
	PasswordCanChange       FileTime
	PasswordMustChange      FileTime
	EffectiveName           RPC_UnicodeString
	FullName                RPC_UnicodeString
	LogonScript             RPC_UnicodeString
	ProfilePath             RPC_UnicodeString
	HomeDirectory           RPC_UnicodeString
	HomeDirectoryDrive      RPC_UnicodeString
	LogonCount              uint16
	BadPasswordCount        uint16
	UserID                  uint32
	PrimaryGroupID          uint32
	GroupCount              uint32
	pGroupIDs               uint32
	GroupIDs                []GroupMembership
	UserFlags               uint32
	UserSessionKey          UserSessionKey
	LogonServer             RPC_UnicodeString
	LogonDomainName         RPC_UnicodeString
	pLogonDomainID          uint32
	LogonDomainID           RPC_SID
	Reserved1               []uint32 // Has 2 elements
	UserAccountControl      uint32
	SubAuthStatus           uint32
	LastSuccessfulILogon    FileTime
	LastFailedILogon        FileTime
	FailedILogonCount       uint32
	Reserved3               uint32
	SIDCount                uint32
	pExtraSIDs              uint32
	ExtraSIDs               []KerbSidAndAttributes
	pResourceGroupDomainSID uint32
	ResourceGroupDomainSID  RPC_SID
	ResourceGroupCount      uint32
	pResourceGroupIDs       uint32
	ResourceGroupIDs        []GroupMembership
}

func (k *KerbValidationInfo) ReadFromStream(b []byte) (err error) {
	ch, p, err := ndr.GetCommonHeader(b)
	if err != nil {
		return fmt.Errorf("Error parsing common header: %v", err)
	}
	e := &ch.Endianness
	_, err = ndr.GetPrivateHeader(b, &p, e)
	if err != nil {
		return fmt.Errorf("Error parsing private header: %v", err)
	}

	//The next 4 bytes are an RPC unique pointer referent. We just skip these
	p += 4

	k.LogOnTime = Read_FileTime(b, &p, e)
	k.LogOffTime = Read_FileTime(b, &p, e)
	k.KickOffTime = Read_FileTime(b, &p, e)
	k.PasswordLastSet = Read_FileTime(b, &p, e)
	k.PasswordCanChange = Read_FileTime(b, &p, e)
	k.PasswordMustChange = Read_FileTime(b, &p, e)

	k.EffectiveName, err = Read_RPC_UnicodeString(b, &p, e)
	k.FullName, err = Read_RPC_UnicodeString(b, &p, e)
	k.LogonScript, err = Read_RPC_UnicodeString(b, &p, e)
	k.ProfilePath, err = Read_RPC_UnicodeString(b, &p, e)
	k.HomeDirectory, err = Read_RPC_UnicodeString(b, &p, e)
	k.HomeDirectoryDrive, err = Read_RPC_UnicodeString(b, &p, e)
	if err != nil {
		return
	}

	k.LogonCount = ndr.Read_uint16(b, &p, e)
	k.BadPasswordCount = ndr.Read_uint16(b, &p, e)
	k.UserID = ndr.Read_uint32(b, &p, e)
	k.PrimaryGroupID = ndr.Read_uint32(b, &p, e)
	k.GroupCount = ndr.Read_uint32(b, &p, e)
	k.pGroupIDs = ndr.Read_uint32(b, &p, e)

	k.UserFlags = ndr.Read_uint32(b, &p, e)
	k.UserSessionKey = Read_UserSessionKey(b, &p, e)

	k.LogonServer, err = Read_RPC_UnicodeString(b, &p, e)
	k.LogonDomainName, err = Read_RPC_UnicodeString(b, &p, e)
	if err != nil {
		return
	}

	k.pLogonDomainID = ndr.Read_uint32(b, &p, e)

	k.Reserved1 = []uint32{
		ndr.Read_uint32(b, &p, e),
		ndr.Read_uint32(b, &p, e),
	}

	k.UserAccountControl = ndr.Read_uint32(b, &p, e)
	k.SubAuthStatus = ndr.Read_uint32(b, &p, e)
	k.LastSuccessfulILogon = Read_FileTime(b, &p, e)
	k.LastFailedILogon = Read_FileTime(b, &p, e)
	k.FailedILogonCount = ndr.Read_uint32(b, &p, e)
	k.Reserved3 = ndr.Read_uint32(b, &p, e)

	k.SIDCount = ndr.Read_uint32(b, &p, e)
	k.pExtraSIDs = ndr.Read_uint32(b, &p, e)

	k.pResourceGroupDomainSID = ndr.Read_uint32(b, &p, e)
	k.ResourceGroupCount = ndr.Read_uint32(b, &p, e)
	k.pResourceGroupIDs = ndr.Read_uint32(b, &p, e)

	// Populate pointers
	err = k.EffectiveName.UnmarshalString(b, &p, e)
	err = k.FullName.UnmarshalString(b, &p, e)
	err = k.LogonScript.UnmarshalString(b, &p, e)
	err = k.ProfilePath.UnmarshalString(b, &p, e)
	err = k.HomeDirectory.UnmarshalString(b, &p, e)
	err = k.HomeDirectoryDrive.UnmarshalString(b, &p, e)

	if k.GroupCount > 0 {
		ac := ndr.Read_UniDimensionalConformantArrayHeader(b, &p, e)
		if ac != int(k.GroupCount) {
			return errors.New("Error with size of group list")
		}
		g := make([]GroupMembership, k.GroupCount, k.GroupCount)
		for i := range g {
			g[i] = Read_GroupMembership(b, &p, e)
		}
		k.GroupIDs = g
	}

	err = k.LogonServer.UnmarshalString(b, &p, e)
	err = k.LogonDomainName.UnmarshalString(b, &p, e)

	//p += 4 //TODO what is this??? SID size
	k.LogonDomainID, err = Read_RPC_SID(b, &p, e)
	if err != nil {
		return err
	}

	if k.SIDCount > 0 {
		ac := ndr.Read_UniDimensionalConformantArrayHeader(b, &p, e)
		if ac != int(k.SIDCount) {
			return fmt.Errorf("Error with size of ExtraSIDs list. Expected: %d, Actual: %d", k.SIDCount, ac)
		}
		es := make([]KerbSidAndAttributes, k.SIDCount, k.SIDCount)
		attr := make([]uint32, k.SIDCount, k.SIDCount)
		ptr := make([]uint32, k.SIDCount, k.SIDCount)
		for i := range attr {
			ptr[i] = ndr.Read_uint32(b, &p, e)
			attr[i] = ndr.Read_uint32(b, &p, e)
		}
		for i := range es {
			if ptr[i] != 0 {
				s, err := Read_RPC_SID(b, &p, e)
				es[i] = KerbSidAndAttributes{SID: s, Attributes: attr[i]}
				if err != nil {
					return ndr.NDRMalformed{EText: fmt.Sprintf("Could not read ExtraSIDs: %v", err)}
				}
			}
		}
		k.ExtraSIDs = es
	}

	if k.pResourceGroupDomainSID != 0 {
		k.ResourceGroupDomainSID, err = Read_RPC_SID(b, &p, e)
		if err != nil {
			return err
		}
	}

	if k.ResourceGroupCount > 0 {
		ac := ndr.Read_UniDimensionalConformantArrayHeader(b, &p, e)
		if ac != int(k.ResourceGroupCount) {
			return fmt.Errorf("Error with size of ResourceGroup list. Expected: %d, Actual: %d", k.ResourceGroupCount, ac)
		}
		g := make([]GroupMembership, ac, ac)
		for i := range g {
			g[i] = Read_GroupMembership(b, &p, e)
		}
		k.ResourceGroupIDs = g
	}

	//Check that there is only zero padding left
	for _, v := range b[p:] {
		if v != 0 {
			return ndr.NDRMalformed{EText: "Non-zero padding left over at end of data stream"}
		}
	}

	return nil
}
