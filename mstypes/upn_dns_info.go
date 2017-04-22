package mstypes

// https://msdn.microsoft.com/en-us/library/dd240468.aspx
type UPN_DNSInfo struct {
	UPNLength           UShort // An unsigned 16-bit integer in little-endian format that specifies the length, in bytes, of the UPN field.
	UPNOffset           UShort // An unsigned 16-bit integer in little-endian format that contains the offset to the beginning of the buffer, in bytes, from the beginning of the UPN_DNS_INFO structure.
	DNSDomainNameLength UShort
	DNSDomainNameOffset UShort
	Flags               ULong
}

const (
	UPN_NO_UPN_ATTR = 31 // The user account object does not have the userPrincipalName attribute ([MS-ADA3] section 2.349) set. A UPN constructed by concatenating the user name with the DNS domain name of the account domain is provided.
)
