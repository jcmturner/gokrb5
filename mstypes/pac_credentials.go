package mstypes

// https://msdn.microsoft.com/en-us/library/cc237931.aspx

//https://msdn.microsoft.com/en-us/library/cc237953.aspx
type PAC_CredentialsInfo struct {
	Version                      uint32 // A 32-bit unsigned integer in little-endian format that defines the version. MUST be 0x00000000.
	EType                        uint32
	PAC_CredentialData_Encrypted []byte // Key usage number for encryption: KERB_NON_KERB_SALT (16)
}

// https://msdn.microsoft.com/en-us/library/cc237952.aspx
// This structure is encrypted prior to being encoded in any other structures.
// Encryption is performed by first serializing the data structure via Network Data Representation (NDR) encoding, as specified in [MS-RPCE].
// Once serialized, the data is encrypted using the key and cryptographic system selected through the AS protocol and the KRB_AS_REP message
// Fields (for capturing this information) and cryptographic parameters are specified in PAC_CREDENTIAL_INFO (section 2.6.1).
type PAC_CredentialData struct {
	CredentialCount uint32
	Credentials     []SECPKG_SupplementalCred // Size is the value of CredentialCount
}

// https://msdn.microsoft.com/en-us/library/cc237956.aspx
type SECPKG_SupplementalCred struct {
	PackageName    RPC_UnicodeString
	CredentialSize uint32
	Credentials    []uint8 // Is a ptr. Size is the value of CredentialSize
}

// https://msdn.microsoft.com/en-us/library/cc237949.aspx
type NTLM_SupplementalCred struct {
	Version    uint32 // A 32-bit unsigned integer that defines the credential version.This field MUST be 0x00000000.
	Flags      uint32
	LMPassword []byte // A 16-element array of unsigned 8-bit integers that define the LM OWF. The LmPassword member MUST be ignored if the L flag is not set in the Flags member.
	NTPassword []byte // A 16-element array of unsigned 8-bit integers that define the NT OWF. The LtPassword member MUST be ignored if the N flag is not set in the Flags member.
}

const (
	NTLM_SUP_CRED_LMOWF = 31 // Indicates that the LM OWF member is present and valid.
	NTLM_SUP_CRED_NTOWF = 30 // Indicates that the NT OWF member is present and valid.
)
