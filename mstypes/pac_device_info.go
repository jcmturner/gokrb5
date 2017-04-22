package mstypes

// https://msdn.microsoft.com/en-us/library/hh536402.aspx
type PAC_DeviceInfo struct {
	UserID            ULong                   // A 32-bit unsigned integer that contains the RID of the account. If the UserId member equals 0x00000000, the first group SID in this member is the SID for this account.
	PrimaryGroupID    ULong                   // A 32-bit unsigned integer that contains the RID for the primary group to which this account belongs.
	AccountDomainID   RPC_SID                 // A SID structure that contains the SID for the domain of the account.This member is used in conjunction with the UserId, and GroupIds members to create the user and group SIDs for the client.
	AccountGroupCount ULong                   // A 32-bit unsigned integer that contains the number of groups within the account domain to which the account belongs
	AccountGroupIDs   []GroupMembership       // A pointer to a list of GROUP_MEMBERSHIP (section 2.2.2) structures that contains the groups to which the account belongs in the account domain. The number of groups in this list MUST be equal to GroupCount.
	SIDCount          ULong                   // A 32-bit unsigned integer that contains the total number of SIDs present in the ExtraSids member.
	ExtraSIDs         []KerbSidAndAttributes  // A pointer to a list of KERB_SID_AND_ATTRIBUTES structures that contain a list of SIDs corresponding to groups not in domains. If the UserId member equals 0x00000000, the first group SID in this member is the SID for this account.
	DomainGroupCount  ULong                   // A 32-bit unsigned integer that contains the number of domains with groups to which the account belongs.
	DomainGroup       []DomainGroupMembership // A pointer to a list of DOMAIN_GROUP_MEMBERSHIP structures (section 2.2.3) that contains the domains to which the account belongs to a group. The number of sets in this list MUST be equal to DomainCount.
}

// TODO come back to this struct
// https://msdn.microsoft.com/en-us/library/hh554226.aspx
//type PAC_DeviceClaimsInfo struct {
//	Claims ClaimsSetMetadata
//}
