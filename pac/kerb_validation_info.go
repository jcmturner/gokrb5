package pac

import (
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/mstypes"
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
	LogOnTime               mstypes.FileTime
	LogOffTime              mstypes.FileTime
	KickOffTime             mstypes.FileTime
	PasswordLastSet         mstypes.FileTime
	PasswordCanChange       mstypes.FileTime
	PasswordMustChange      mstypes.FileTime
	EffectiveName           mstypes.RPC_UnicodeString
	FullName                mstypes.RPC_UnicodeString
	LogonScript             mstypes.RPC_UnicodeString
	ProfilePath             mstypes.RPC_UnicodeString
	HomeDirectory           mstypes.RPC_UnicodeString
	HomeDirectoryDrive      mstypes.RPC_UnicodeString
	LogonCount              uint16
	BadPasswordCount        uint16
	UserID                  uint32
	PrimaryGroupID          uint32
	GroupCount              uint32
	pGroupIDs               uint32
	GroupIDs                []mstypes.GroupMembership
	UserFlags               uint32
	UserSessionKey          mstypes.UserSessionKey
	LogonServer             mstypes.RPC_UnicodeString
	LogonDomainName         mstypes.RPC_UnicodeString
	pLogonDomainID          uint32
	LogonDomainID           mstypes.RPC_SID
	Reserved1               []uint32 // Has 2 elements
	UserAccountControl      uint32
	SubAuthStatus           uint32
	LastSuccessfulILogon    mstypes.FileTime
	LastFailedILogon        mstypes.FileTime
	FailedILogonCount       uint32
	Reserved3               uint32
	SIDCount                uint32
	pExtraSIDs              uint32
	ExtraSIDs               []mstypes.KerbSidAndAttributes
	pResourceGroupDomainSID uint32
	ResourceGroupDomainSID  mstypes.RPC_SID
	ResourceGroupCount      uint32
	pResourceGroupIDs       uint32
	ResourceGroupIDs        []mstypes.GroupMembership
}

func (k *KerbValidationInfo) Unmarshal(b []byte) (err error) {
	ch, _, p, err := ndr.ReadHeaders(&b)
	if err != nil {
		return fmt.Errorf("Error parsing byte stream headers: %v", err)
	}
	e := &ch.Endianness

	//The next 4 bytes are an RPC unique pointer referent. We just skip these
	p += 4

	k.LogOnTime = mstypes.Read_FileTime(&b, &p, e)
	k.LogOffTime = mstypes.Read_FileTime(&b, &p, e)
	k.KickOffTime = mstypes.Read_FileTime(&b, &p, e)
	k.PasswordLastSet = mstypes.Read_FileTime(&b, &p, e)
	k.PasswordCanChange = mstypes.Read_FileTime(&b, &p, e)
	k.PasswordMustChange = mstypes.Read_FileTime(&b, &p, e)

	k.EffectiveName, err = mstypes.Read_RPC_UnicodeString(&b, &p, e)
	k.FullName, err = mstypes.Read_RPC_UnicodeString(&b, &p, e)
	k.LogonScript, err = mstypes.Read_RPC_UnicodeString(&b, &p, e)
	k.ProfilePath, err = mstypes.Read_RPC_UnicodeString(&b, &p, e)
	k.HomeDirectory, err = mstypes.Read_RPC_UnicodeString(&b, &p, e)
	k.HomeDirectoryDrive, err = mstypes.Read_RPC_UnicodeString(&b, &p, e)
	if err != nil {
		return
	}

	k.LogonCount = ndr.Read_uint16(&b, &p, e)
	k.BadPasswordCount = ndr.Read_uint16(&b, &p, e)
	k.UserID = ndr.Read_uint32(&b, &p, e)
	k.PrimaryGroupID = ndr.Read_uint32(&b, &p, e)
	k.GroupCount = ndr.Read_uint32(&b, &p, e)
	k.pGroupIDs = ndr.Read_uint32(&b, &p, e)

	k.UserFlags = ndr.Read_uint32(&b, &p, e)
	k.UserSessionKey = mstypes.Read_UserSessionKey(&b, &p, e)

	k.LogonServer, err = mstypes.Read_RPC_UnicodeString(&b, &p, e)
	k.LogonDomainName, err = mstypes.Read_RPC_UnicodeString(&b, &p, e)
	if err != nil {
		return
	}

	k.pLogonDomainID = ndr.Read_uint32(&b, &p, e)

	k.Reserved1 = []uint32{
		ndr.Read_uint32(&b, &p, e),
		ndr.Read_uint32(&b, &p, e),
	}

	k.UserAccountControl = ndr.Read_uint32(&b, &p, e)
	k.SubAuthStatus = ndr.Read_uint32(&b, &p, e)
	k.LastSuccessfulILogon = mstypes.Read_FileTime(&b, &p, e)
	k.LastFailedILogon = mstypes.Read_FileTime(&b, &p, e)
	k.FailedILogonCount = ndr.Read_uint32(&b, &p, e)
	k.Reserved3 = ndr.Read_uint32(&b, &p, e)

	k.SIDCount = ndr.Read_uint32(&b, &p, e)
	k.pExtraSIDs = ndr.Read_uint32(&b, &p, e)

	k.pResourceGroupDomainSID = ndr.Read_uint32(&b, &p, e)
	k.ResourceGroupCount = ndr.Read_uint32(&b, &p, e)
	k.pResourceGroupIDs = ndr.Read_uint32(&b, &p, e)

	// Populate pointers
	err = k.EffectiveName.UnmarshalString(&b, &p, e)
	err = k.FullName.UnmarshalString(&b, &p, e)
	err = k.LogonScript.UnmarshalString(&b, &p, e)
	err = k.ProfilePath.UnmarshalString(&b, &p, e)
	err = k.HomeDirectory.UnmarshalString(&b, &p, e)
	err = k.HomeDirectoryDrive.UnmarshalString(&b, &p, e)

	if k.GroupCount > 0 {
		ac := ndr.Read_UniDimensionalConformantArrayHeader(&b, &p, e)
		if ac != int(k.GroupCount) {
			return errors.New("Error with size of group list")
		}
		g := make([]mstypes.GroupMembership, k.GroupCount, k.GroupCount)
		for i := range g {
			g[i] = mstypes.Read_GroupMembership(&b, &p, e)
		}
		k.GroupIDs = g
	}

	err = k.LogonServer.UnmarshalString(&b, &p, e)
	err = k.LogonDomainName.UnmarshalString(&b, &p, e)

	if k.pLogonDomainID != 0 {
		k.LogonDomainID, err = mstypes.Read_RPC_SID(&b, &p, e)
		if err != nil {
			return fmt.Errorf("Error reading LogonDomainID: %v", err)
		}
	}

	if k.SIDCount > 0 {
		ac := ndr.Read_UniDimensionalConformantArrayHeader(&b, &p, e)
		if ac != int(k.SIDCount) {
			return fmt.Errorf("Error with size of ExtraSIDs list. Expected: %d, Actual: %d", k.SIDCount, ac)
		}
		es := make([]mstypes.KerbSidAndAttributes, k.SIDCount, k.SIDCount)
		attr := make([]uint32, k.SIDCount, k.SIDCount)
		ptr := make([]uint32, k.SIDCount, k.SIDCount)
		for i := range attr {
			ptr[i] = ndr.Read_uint32(&b, &p, e)
			attr[i] = ndr.Read_uint32(&b, &p, e)
		}
		for i := range es {
			if ptr[i] != 0 {
				s, err := mstypes.Read_RPC_SID(&b, &p, e)
				es[i] = mstypes.KerbSidAndAttributes{SID: s, Attributes: attr[i]}
				if err != nil {
					return ndr.NDRMalformed{EText: fmt.Sprintf("Could not read ExtraSIDs: %v", err)}
				}
			}
		}
		k.ExtraSIDs = es
	}

	if k.pResourceGroupDomainSID != 0 {
		k.ResourceGroupDomainSID, err = mstypes.Read_RPC_SID(&b, &p, e)
		if err != nil {
			return err
		}
	}

	if k.ResourceGroupCount > 0 {
		ac := ndr.Read_UniDimensionalConformantArrayHeader(&b, &p, e)
		if ac != int(k.ResourceGroupCount) {
			return fmt.Errorf("Error with size of ResourceGroup list. Expected: %d, Actual: %d", k.ResourceGroupCount, ac)
		}
		g := make([]mstypes.GroupMembership, ac, ac)
		for i := range g {
			g[i] = mstypes.Read_GroupMembership(&b, &p, e)
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

func (k *KerbValidationInfo) GetGroupMembershipSIDs() []string {
	gSize := len(k.GroupIDs) + len(k.ExtraSIDs)
	g := make([]string, gSize, gSize)
	lSID := k.LogonDomainID.ToString()
	for i := range k.GroupIDs {
		g[i] = fmt.Sprintf("%s-%d", lSID, k.GroupIDs[i].RelativeID)
	}
	for _, s := range k.ExtraSIDs {
		var exists = false
		for _, es := range g {
			if es == s.SID.ToString() {
				exists = true
				break
			}
		}
		if !exists {
			g = append(g, s.SID.ToString())
		}
	}
	for _, r := range k.ResourceGroupIDs {
		var exists = false
		s := fmt.Sprintf("%s-%d", lSID, r)
		for _, es := range g {
			if es == s {
				exists = true
				break
			}
		}
		if !exists {
			g = append(g, s)
		}
	}
	return g
}
