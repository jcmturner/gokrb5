package mstypes

const (
	ULTYPE_KERB_VALIDATION_INFO      = 1
	ULTYPE_CREDENTIALS               = 2
	ULTYPE_PAC_SERVER_SIGNATURE_DATA = 6
	ULTYPE_PAC_KDC_SIGNATURE_DATA    = 7
	ULTYPE_PAC_CLIENT_INFO           = 10
	ULTYPE_S4U_DELEGATION_INFO       = 11
	ULTYPE_UPN_DNS_INFO              = 12
	ULTYPE_PAC_CLIENT_CLAIMS_INFO    = 13
	ULTYPE_PAC_DEVICE_INFO           = 14
	ULTYPE_PAC_DEVICE_CLAIMS_INFO    = 15
)

// https://msdn.microsoft.com/en-us/library/cc237954.aspx
type PACInfoBuffer struct {
	ULType       ULong   // A 32-bit unsigned integer in little-endian format that describes the type of data present in the buffer contained at Offset.
	CBBufferSize ULong   // A 32-bit unsigned integer in little-endian format that contains the size, in bytes, of the buffer in the PAC located at Offset.
	Offset       ULong64 // A 64-bit unsigned integer in little-endian format that contains the offset to the beginning of the buffer, in bytes, from the beginning of the PACTYPE structure. The data offset MUST be a multiple of eight. The following sections specify the format of each type of element.
}
