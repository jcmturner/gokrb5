package types

// Reference: https://www.ietf.org/rfc/rfc4556.txt
// PKINIT - Public Key Cryptography for Initial Authentication in Kerberos

import (
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/patype"
)

// PA-PK-AS-REQ ::= SEQUENCE {
//     signedAuthPack          [0] IMPLICIT OCTET STRING,
//     trustedCertifiers       [1] ExternalPrincipalIdentifier OPTIONAL,
//     kdcPkId                 [2] IMPLICIT OCTET STRING OPTIONAL
// }
type PAPKASReq struct {
	SignedAuthPack []byte `asn1:"tag:0"`
	// TrustedCertifiers and KDCPkID are optional and not implemented
}

// AuthPack ::= SEQUENCE {
//     pkAuthenticator         [0] PKAuthenticator,
//     clientPublicValue       [1] SubjectPublicKeyInfo OPTIONAL,
//     supportedCMSTypes       [2] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
//     clientDHNonce           [3] DHNonce OPTIONAL
// }
type AuthPack struct {
	PKAuthenticator   PKAuthenticator       `asn1:"tag:0,explicit"`
	ClientPublicValue SubjectPublicKeyInfo  `asn1:"tag:1,explicit,optional"`
	SupportedCMSTypes []AlgorithmIdentifier `asn1:"tag:2,explicit,optional"`
	ClientDHNonce     []byte                `asn1:"tag:3,explicit,optional"` // DHNonce
}

// PKAuthenticator ::= SEQUENCE {
//     cusec                   [0] INTEGER (0..999999),
//     ctime                   [1] KerberosTime,
//     nonce                   [2] INTEGER (0..4294967295),
//     paChecksum              [3] OCTET STRING
// }
type PKAuthenticator struct {
	Cusec      int       `asn1:"tag:0,explicit"`
	Ctime      time.Time `asn1:"tag:1,explicit,generalized"`
	Nonce      int       `asn1:"tag:2,explicit"`
	PAChecksum []byte    `asn1:"tag:3,explicit,optional"`
}

// SubjectPublicKeyInfo for Diffie-Hellman public key
// SubjectPublicKeyInfo ::= SEQUENCE {
//     algorithm               AlgorithmIdentifier,
//     subjectPublicKey        BIT STRING
// }
type SubjectPublicKeyInfo struct {
	Algorithm        AlgorithmIdentifier `asn1:""`
	SubjectPublicKey asn1.BitString      `asn1:""`
}

// AlgorithmIdentifier ::= SEQUENCE {
//     algorithm               OBJECT IDENTIFIER,
//     parameters              ANY DEFINED BY algorithm OPTIONAL
// }
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier `asn1:""`
	Parameters asn1.RawValue         `asn1:"optional"`
}

// PA-PK-AS-REP ::= CHOICE {
//     dhInfo                  [0] DHRepInfo,
//     encKeyPack              [1] IMPLICIT OCTET STRING
// }
// We use RawValue and decode based on the tag
type PAPKASRep struct {
	DHInfo asn1.RawValue
}

// DHRepInfo ::= SEQUENCE {
//     dhSignedData            [0] IMPLICIT OCTET STRING,
//     serverDHNonce           [1] DHNonce OPTIONAL
// }
type DHRepInfo struct {
	DHSignedData  []byte `asn1:"tag:0"`
	ServerDHNonce []byte `asn1:"explicit,optional,tag:1"` // DHNonce
}

// KDCDHKeyInfo ::= SEQUENCE {
//     subjectPublicKey        [0] BIT STRING,
//     nonce                   [1] INTEGER (0..4294967295),
//     dhKeyExpiration         [2] KerberosTime OPTIONAL
// }
type KDCDHKeyInfo struct {
	SubjectPublicKey asn1.BitString `asn1:"tag:0,explicit"`
	Nonce            int            `asn1:"tag:1,explicit"`
	DHKeyExpiration  time.Time      `asn1:"tag:2,explicit,optional,generalized"`
}

// ReplyKeyPack ::= SEQUENCE {
//     replyKey                [0] EncryptionKey,
//     asChecksum              [1] Checksum
// }
type ReplyKeyPack struct {
	ReplyKey   EncryptionKey `asn1:"explicit,tag:0"`
	ASChecksum Checksum      `asn1:"explicit,tag:1"`
}

// DHNonce ::= OCTET STRING (SIZE(1..MAX))
// Represented as []byte in Go

// Marshal methods for PKINIT structures

// Marshal the PAPKASReq
func (p *PAPKASReq) Marshal() ([]byte, error) {
	return asn1.Marshal(*p)
}

// Unmarshal bytes into the PAPKASReq
func (p *PAPKASReq) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, p)
	return err
}

// Marshal the AuthPack
func (a *AuthPack) Marshal() ([]byte, error) {
	return asn1.Marshal(*a)
}

// Unmarshal bytes into the AuthPack
func (a *AuthPack) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}

// Marshal the PKAuthenticator
func (p *PKAuthenticator) Marshal() ([]byte, error) {
	return asn1.Marshal(*p)
}

// Unmarshal bytes into the PKAuthenticator
func (p *PKAuthenticator) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, p)
	return err
}

// Marshal the PAPKASRep
func (p *PAPKASRep) Marshal() ([]byte, error) {
	return asn1.Marshal(*p)
}

// Unmarshal bytes into the PAPKASRep
func (p *PAPKASRep) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, p)
	return err
}

// Marshal the DHRepInfo
func (d *DHRepInfo) Marshal() ([]byte, error) {
	return asn1.Marshal(*d)
}

// Unmarshal bytes into the DHRepInfo
func (d *DHRepInfo) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, d)
	return err
}

// Marshal the KDCDHKeyInfo
func (k *KDCDHKeyInfo) Marshal() ([]byte, error) {
	return asn1.Marshal(*k)
}

// Unmarshal bytes into the KDCDHKeyInfo
func (k *KDCDHKeyInfo) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, k)
	return err
}

// Marshal the ReplyKeyPack
func (r *ReplyKeyPack) Marshal() ([]byte, error) {
	return asn1.Marshal(*r)
}

// Unmarshal bytes into the ReplyKeyPack
func (r *ReplyKeyPack) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, r)
	return err
}

// Helper methods for PAData integration

// GetPAPKASReq returns a PAPKASReq from the PAData.
func (pa *PAData) GetPAPKASReq() (d PAPKASReq, err error) {
	if pa.PADataType != patype.PA_PK_AS_REQ {
		err = fmt.Errorf("PAData does not contain PA-PK-AS-REQ data. TypeID Expected: %v; Actual: %v", patype.PA_PK_AS_REQ, pa.PADataType)
		return
	}
	_, err = asn1.Unmarshal(pa.PADataValue, &d)
	return
}

// GetPAPKASRep returns a PAPKASRep from the PAData.
func (pa *PAData) GetPAPKASRep() (d PAPKASRep, err error) {
	if pa.PADataType != patype.PA_PK_AS_REP {
		err = fmt.Errorf("PAData does not contain PA-PK-AS-REP data. TypeID Expected: %v; Actual: %v", patype.PA_PK_AS_REP, pa.PADataType)
		return
	}
	_, err = asn1.Unmarshal(pa.PADataValue, &d)
	return
}

// NewPKAuthenticator creates a new PKAuthenticator with the current time and provided nonce and checksum.
func NewPKAuthenticator(nonce int, paChecksum []byte) PKAuthenticator {
	t := time.Now().UTC()
	return PKAuthenticator{
		Cusec:      int((t.UnixNano() / int64(time.Microsecond)) - (t.Unix() * 1e6)),
		Ctime:      t,
		Nonce:      nonce,
		PAChecksum: paChecksum,
	}
}
