package mstypes

import (
	"encoding/binary"
	"github.com/jcmturner/gokrb5/ndr"
)

// https://msdn.microsoft.com/en-us/library/hh536402.aspx
type PAC_DeviceInfo struct {
	UserID            uint32                  // A 32-bit unsigned integer that contains the RID of the account. If the UserId member equals 0x00000000, the first group SID in this member is the SID for this account.
	PrimaryGroupID    uint32                  // A 32-bit unsigned integer that contains the RID for the primary group to which this account belongs.
	AccountDomainID   RPC_SID                 // A SID structure that contains the SID for the domain of the account.This member is used in conjunction with the UserId, and GroupIds members to create the user and group SIDs for the client.
	AccountGroupCount uint32                  // A 32-bit unsigned integer that contains the number of groups within the account domain to which the account belongs
	AccountGroupIDs   []GroupMembership       // A pointer to a list of GROUP_MEMBERSHIP (section 2.2.2) structures that contains the groups to which the account belongs in the account domain. The number of groups in this list MUST be equal to GroupCount.
	SIDCount          uint32                  // A 32-bit unsigned integer that contains the total number of SIDs present in the ExtraSids member.
	ExtraSIDs         []KerbSidAndAttributes  // A pointer to a list of KERB_SID_AND_ATTRIBUTES structures that contain a list of SIDs corresponding to groups not in domains. If the UserId member equals 0x00000000, the first group SID in this member is the SID for this account.
	DomainGroupCount  uint32                  // A 32-bit unsigned integer that contains the number of domains with groups to which the account belongs.
	DomainGroup       []DomainGroupMembership // A pointer to a list of DOMAIN_GROUP_MEMBERSHIP structures (section 2.2.3) that contains the domains to which the account belongs to a group. The number of sets in this list MUST be equal to DomainCount.
}

func Read_PAC_DeviceInfo(b []byte, p *int, e *binary.ByteOrder) PAC_DeviceInfo {
	u := ndr.Read_uint32(b, p, e)
	pg := ndr.Read_uint32(b, p, e)
	aSid, _ := Read_RPC_SID(b, p, e)
	c := ndr.Read_uint32(b, p, e)
	ag := make([]GroupMembership, c, c)
	for i := range ag {
		ag[i] = Read_GroupMembership(b, p, e)
	}
	sc := ndr.Read_uint32(b, p, e)
	eSid := make([]KerbSidAndAttributes, sc, sc)
	for i := range eSid {
		eSid[i], _ = Read_KerbSidAndAttributes(b, p, e)
	}
	dc := ndr.Read_uint32(b, p, e)
	dg := make([]DomainGroupMembership, dc, dc)
	for i := range dg {
		dg[i], _ = Read_DomainGroupMembership(b, p, e)
	}
	return PAC_DeviceInfo{
		UserID:            u,
		PrimaryGroupID:    pg,
		AccountDomainID:   aSid,
		AccountGroupCount: c,
		AccountGroupIDs:   ag,
		SIDCount:          sc,
		ExtraSIDs:         eSid,
		DomainGroupCount:  dc,
		DomainGroup:       dg,
	}
}

// TODO come back to this struct
// https://msdn.microsoft.com/en-us/library/hh554226.aspx
//type PAC_DeviceClaimsInfo struct {
//	Claims ClaimsSetMetadata
//}
