package pac

import (
	"encoding/binary"
	"fmt"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/iana/keyusage"
	"github.com/jcmturner/gokrb5/mstypes"
	"github.com/jcmturner/gokrb5/ndr"
	"github.com/jcmturner/gokrb5/types"
)

// https://msdn.microsoft.com/en-us/library/cc237931.aspx

// https://msdn.microsoft.com/en-us/library/cc237953.aspx
type PAC_CredentialsInfo struct {
	Version                      uint32 // A 32-bit unsigned integer in little-endian format that defines the version. MUST be 0x00000000.
	EType                        uint32
	PAC_CredentialData_Encrypted []byte // Key usage number for encryption: KERB_NON_KERB_SALT (16)
	PAC_CredentialData           PAC_CredentialData
}

func (c *PAC_CredentialsInfo) Unmarshal(b []byte, k types.EncryptionKey) error {
	ch, _, p, err := ndr.ReadHeaders(&b)
	if err != nil {
		return fmt.Errorf("Error parsing byte stream headers: %v", err)
	}
	e := &ch.Endianness

	//The next 4 bytes are an RPC unique pointer referent. We just skip these
	p += 4

	c.Version = ndr.Read_uint32(&b, &p, e)
	c.EType = ndr.Read_uint32(&b, &p, e)
	c.PAC_CredentialData_Encrypted = ndr.Read_bytes(&b, &p, len(b)-p, e)

	err = c.DecryptEncPart(k, e)
	if err != nil {
		return fmt.Errorf("Error decrypting PAC Credentials Data: %v", err)
	}
	return nil
}

func (c *PAC_CredentialsInfo) DecryptEncPart(k types.EncryptionKey, e *binary.ByteOrder) error {
	if k.KeyType != int(c.EType) {
		return fmt.Errorf("Key provided is not the correct type. Type needed: %d, type provided: %d", c.EType, k.KeyType)
	}
	pt, err := crypto.DecryptMessage(c.PAC_CredentialData_Encrypted, k, keyusage.KERB_NON_KERB_SALT)
	if err != nil {
		return err
	}
	var p int
	c.PAC_CredentialData = Read_PAC_CredentialData(&pt, &p, e)
	return nil
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

func Read_PAC_CredentialData(b *[]byte, p *int, e *binary.ByteOrder) PAC_CredentialData {
	c := ndr.Read_uint32(b, p, e)
	cr := make([]SECPKG_SupplementalCred, c, c)
	for i := range cr {
		cr[i] = Read_SECPKG_SupplementalCred(b, p, e)
	}
	return PAC_CredentialData{
		CredentialCount: c,
		Credentials:     cr,
	}
}

// https://msdn.microsoft.com/en-us/library/cc237956.aspx
type SECPKG_SupplementalCred struct {
	PackageName    mstypes.RPC_UnicodeString
	CredentialSize uint32
	Credentials    []uint8 // Is a ptr. Size is the value of CredentialSize
}

func Read_SECPKG_SupplementalCred(b *[]byte, p *int, e *binary.ByteOrder) SECPKG_SupplementalCred {
	n, _ := mstypes.Read_RPC_UnicodeString(b, p, e)
	cs := ndr.Read_uint32(b, p, e)
	c := make([]uint8, cs, cs)
	for i := range c {
		c[i] = ndr.Read_uint8(b, p)
	}
	return SECPKG_SupplementalCred{
		PackageName:    n,
		CredentialSize: cs,
		Credentials:    c,
	}
}

// https://msdn.microsoft.com/en-us/library/cc237949.aspx
type NTLM_SupplementalCred struct {
	Version    uint32 // A 32-bit unsigned integer that defines the credential version.This field MUST be 0x00000000.
	Flags      uint32
	LMPassword []byte // A 16-element array of unsigned 8-bit integers that define the LM OWF. The LmPassword member MUST be ignored if the L flag is not set in the Flags member.
	NTPassword []byte // A 16-element array of unsigned 8-bit integers that define the NT OWF. The LtPassword member MUST be ignored if the N flag is not set in the Flags member.
}

func Read_NTLM_SupplementalCred(b *[]byte, p *int, e *binary.ByteOrder) NTLM_SupplementalCred {
	v := ndr.Read_uint32(b, p, e)
	f := ndr.Read_uint32(b, p, e)
	l := ndr.Read_bytes(b, p, 16, e)
	n := ndr.Read_bytes(b, p, 16, e)
	return NTLM_SupplementalCred{
		Version:    v,
		Flags:      f,
		LMPassword: l,
		NTPassword: n,
	}
}

const (
	NTLM_SUP_CRED_LMOWF = 31 // Indicates that the LM OWF member is present and valid.
	NTLM_SUP_CRED_NTOWF = 30 // Indicates that the NT OWF member is present and valid.
)
