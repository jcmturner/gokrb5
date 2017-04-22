package mstypes

// https://msdn.microsoft.com/en-us/library/cc237951.aspx
type PAC_ClientInfo struct {
	ClientID   FileTime // A FILETIME structure in little-endian format that contains the Kerberos initial ticket-granting ticket TGT authentication time
	NameLength UShort   // An unsigned 16-bit integer in little-endian format that specifies the length, in bytes, of the Name field.
	Name       []WChar  // An array of 16-bit Unicode characters in little-endian format that contains the client's account name.
}

// TODO come back to this struct
// https://msdn.microsoft.com/en-us/library/hh536365.aspx
//type PAC_ClientClaimsInfo struct {
//	Claims ClaimsSetMetadata
//}
