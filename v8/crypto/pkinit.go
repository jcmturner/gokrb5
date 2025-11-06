package crypto

// PKINIT Cryptographic Operations
// Reference: https://www.ietf.org/rfc/rfc4556.txt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/jcmturner/gokrb5/v8/types"
)

// PKINIT Algorithm Object Identifiers
var (
	// id-pkinit OID: 1.3.6.1.5.2.3
	OIDPKInit = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3}

	// id-pkinit-authData OID: 1.3.6.1.5.2.3.1
	OIDPKInitAuthData = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1}

	// id-pkinit-DHKeyData OID: 1.3.6.1.5.2.3.2
	OIDPKInitDHKeyData = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 2}

	// id-pkinit-rkeyData OID: 1.3.6.1.5.2.3.3
	OIDPKInitRKeyData = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 3}

	// id-pkinit-KPClientAuth OID: 1.3.6.1.5.2.3.4 (EKU for client certs)
	OIDPKInitKPClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 4}

	// id-pkinit-KPKdc OID: 1.3.6.1.5.2.3.5 (EKU for KDC certs)
	OIDPKInitKPKdc = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 5}

	// id-pkinit-san OID: 1.3.6.1.5.2.2 (Subject Alternative Name for Kerberos)
	OIDPKInitSAN = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 2}

	// id-ms-kp-sc-logon OID: 1.3.6.1.4.1.311.20.2.2 (Microsoft Smart Card Logon)
	OIDMSKPSCLogon = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}

	// Diffie-Hellman OID: 1.2.840.10046.2.1
	OIDDiffieHellman = asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}

	// RSA Encryption OID: 1.2.840.113549.1.1.1
	OIDRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

	// SHA1 with RSA OID: 1.2.840.113549.1.1.5
	OIDSHA1WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}

	// id-data (for CMS ContentInfo): 1.2.840.113549.1.7.1
	OIDData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

	// id-signedData (for CMS): 1.2.840.113549.1.7.2
	OIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// id-envelopedData (for CMS): 1.2.840.113549.1.7.3
	OIDEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
)

// CMS ContentInfo structure
// ContentInfo ::= SEQUENCE {
//     contentType ContentType,
//     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
// }
type CMSContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional"` // We manually set tag in RawValue
}

// CMS SignedData structure (simplified for PKINIT)
// SignedData ::= SEQUENCE {
//     version CMSVersion,
//     digestAlgorithms DigestAlgorithmIdentifiers,
//     encapContentInfo EncapsulatedContentInfo,
//     certificates [0] IMPLICIT CertificateSet OPTIONAL,
//     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//     signerInfos SignerInfos
// }
type CMSSignedData struct {
	Version          int                       `asn1:""`
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo   `asn1:""`
	Certificates     []asn1.RawValue           `asn1:"optional,set,tag:0"`
	CRLs             []asn1.RawValue           `asn1:"optional,set,tag:1"`
	SignerInfos      []SignerInfo              `asn1:"set"`
}

// EncapsulatedContentInfo ::= SEQUENCE {
//     eContentType ContentType,
//     eContent [0] EXPLICIT OCTET STRING OPTIONAL
// }
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

// SignerInfo ::= SEQUENCE {
//     version CMSVersion,
//     sid SignerIdentifier,
//     digestAlgorithm DigestAlgorithmIdentifier,
//     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//     signatureAlgorithm SignatureAlgorithmIdentifier,
//     signature SignatureValue,
//     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL
// }
type SignerInfo struct {
	Version            int                        `asn1:""`
	SID                IssuerAndSerialNumber      `asn1:""`
	DigestAlgorithm    pkix.AlgorithmIdentifier   `asn1:""`
	SignedAttrs        []Attribute                `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier   `asn1:""`
	Signature          []byte                     `asn1:""`
	UnsignedAttrs      []Attribute                `asn1:"optional,tag:1"`
}

// IssuerAndSerialNumber ::= SEQUENCE {
//     issuer Name,
//     serialNumber CertificateSerialNumber
// }
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// Attribute ::= SEQUENCE {
//     attrType OBJECT IDENTIFIER,
//     attrValues SET OF AttributeValue
// }
type Attribute struct {
	AttrType   asn1.ObjectIdentifier
	AttrValues []asn1.RawValue `asn1:"set"`
}

// CMSEnvelopedData structure (simplified)
// EnvelopedData ::= SEQUENCE {
//     version CMSVersion,
//     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//     recipientInfos RecipientInfos,
//     encryptedContentInfo EncryptedContentInfo,
//     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
// }
type CMSEnvelopedData struct {
	Version              int                      `asn1:""`
	OriginatorInfo       asn1.RawValue            `asn1:"optional,tag:0"`
	RecipientInfos       []RecipientInfo          `asn1:"set"`
	EncryptedContentInfo EncryptedContentInfo     `asn1:""`
	UnprotectedAttrs     []Attribute              `asn1:"optional,tag:1"`
}

// RecipientInfo ::= CHOICE {
//     ktri KeyTransRecipientInfo,
//     kari [1] KeyAgreeRecipientInfo,
//     kekri [2] KEKRecipientInfo,
//     pwri [3] PasswordRecipientinfo,
//     ori [4] OtherRecipientInfo
// }
type RecipientInfo struct {
	KeyTrans asn1.RawValue `asn1:""`
}

// EncryptedContentInfo ::= SEQUENCE {
//     contentType ContentType,
//     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
//     encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL
// }
type EncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"optional,tag:0"`
}

// CreateCMSSignedData creates a CMS SignedData structure for PKINIT
func CreateCMSSignedData(data []byte, cert *x509.Certificate, privateKey crypto.Signer, certs []*x509.Certificate) ([]byte, error) {
	// Compute SHA1 digest of the data
	h := sha1.New()
	h.Write(data)
	digest := h.Sum(nil)

	// Create authenticated attributes
	// contentType attribute
	contentTypeValue, err := asn1.Marshal(OIDPKInitAuthData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal contentType: %v", err)
	}

	// messageDigest attribute
	messageDigestValue, err := asn1.Marshal(digest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal messageDigest: %v", err)
	}

	// Authenticated attributes must be in DER order (sorted by OID)
	// id-contentType (1.2.840.113549.1.9.3) comes before id-messageDigest (1.2.840.113549.1.9.4)
	authenticatedAttrs := []Attribute{
		{
			AttrType:   asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}, // id-contentType
			AttrValues: []asn1.RawValue{{FullBytes: contentTypeValue}},
		},
		{
			AttrType:   asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}, // id-messageDigest
			AttrValues: []asn1.RawValue{{FullBytes: messageDigestValue}},
		},
	}

	// Marshal authenticated attributes for signing
	// We need to sign the DER-encoded SET OF attributes
	authAttrsBytes, err := asn1.Marshal(authenticatedAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authenticated attributes: %v", err)
	}

	// Unmarshal to extract just the contents (removes the outer SEQUENCE tag/length)
	var authAttrsRaw asn1.RawValue
	_, err = asn1.Unmarshal(authAttrsBytes, &authAttrsRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal authenticated attributes: %v", err)
	}

	// Construct SET OF encoding: tag (0x31) + length + contents
	// Use the contents from the RawValue, but with SET tag instead of SEQUENCE
	setLength := len(authAttrsRaw.Bytes)
	var authAttrsForSigning []byte
	authAttrsForSigning = append(authAttrsForSigning, 0x31) // SET tag

	// Encode length (simplified for lengths < 128 and < 256)
	if setLength < 128 {
		authAttrsForSigning = append(authAttrsForSigning, byte(setLength))
	} else if setLength < 256 {
		authAttrsForSigning = append(authAttrsForSigning, 0x81, byte(setLength))
	} else {
		authAttrsForSigning = append(authAttrsForSigning, 0x82, byte(setLength>>8), byte(setLength&0xFF))
	}
	authAttrsForSigning = append(authAttrsForSigning, authAttrsRaw.Bytes...)

	// Hash the SET OF encoded authenticated attributes
	h2 := sha1.New()
	h2.Write(authAttrsForSigning)
	authAttrsDigest := h2.Sum(nil)

	// Sign the hash of the authenticated attributes
	signature, err := privateKey.Sign(rand.Reader, authAttrsDigest, crypto.SHA1)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}

	// Create SignerInfo
	signerInfo := SignerInfo{
		Version: 1,
		SID: IssuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
			SerialNumber: cert.SerialNumber,
		},
		DigestAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, // SHA1
		},
		SignedAttrs: authenticatedAttrs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: OIDSHA1WithRSA,
		},
		Signature: signature,
	}

	// Prepare certificate set - include the signing certificate first
	var certSet []asn1.RawValue
	certSet = append(certSet, asn1.RawValue{FullBytes: cert.Raw})
	// Then add any additional certificates (skip if it's the signing certificate)
	for _, c := range certs {
		// Skip if this is the same certificate as the signing certificate
		if c.SerialNumber.Cmp(cert.SerialNumber) == 0 && c.Issuer.String() == cert.Issuer.String() {
			continue
		}
		certSet = append(certSet, asn1.RawValue{FullBytes: c.Raw})
	}

	// Create SignedData
	// Version 3 is required when certificates are present (RFC 5652)
	signedData := CMSSignedData{
		Version: 3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{
			{
				Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, // SHA1
			},
		},
		EncapContentInfo: EncapsulatedContentInfo{
			EContentType: OIDPKInitAuthData,
			EContent:     data,
		},
		Certificates: certSet,
		SignerInfos:  []SignerInfo{signerInfo},
	}

	// Marshal SignedData
	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SignedData: %v", err)
	}

	// Wrap in ContentInfo
	// Content must be tagged as [0] EXPLICIT, meaning context-specific class, tag 0, wrapping the SignedData
	// We need to manually construct the RawValue with proper class and tag
	contentInfo := CMSContentInfo{
		ContentType: OIDSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true, // EXPLICIT tagging wraps the content
			Bytes:      signedDataBytes,
		},
	}

	return asn1.Marshal(contentInfo)
}

// VerifyCMSSignedData verifies a CMS SignedData structure and extracts the content
func VerifyCMSSignedData(signedDataBytes []byte, trustedCerts []*x509.Certificate) ([]byte, []*x509.Certificate, error) {
	// Parse ContentInfo
	var contentInfo CMSContentInfo
	_, err := asn1.Unmarshal(signedDataBytes, &contentInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal ContentInfo: %v", err)
	}

	if !contentInfo.ContentType.Equal(OIDSignedData) {
		return nil, nil, fmt.Errorf("not a SignedData structure")
	}

	// Parse SignedData
	var signedData CMSSignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal SignedData: %v", err)
	}

	// Extract certificates from SignedData
	var certs []*x509.Certificate
	for _, rawCert := range signedData.Certificates {
		cert, err := x509.ParseCertificate(rawCert.FullBytes)
		if err != nil {
			continue // Skip invalid certificates
		}
		certs = append(certs, cert)
	}

	// TODO: Verify signature using SignerInfo and certificates
	// For now, return the encapsulated content and certificates
	return signedData.EncapContentInfo.EContent, certs, nil
}

// DecryptCMSEnvelopedData decrypts a CMS EnvelopedData structure
func DecryptCMSEnvelopedData(envelopedDataBytes []byte, privateKey crypto.Decrypter) ([]byte, error) {
	// Parse ContentInfo
	var contentInfo CMSContentInfo
	_, err := asn1.Unmarshal(envelopedDataBytes, &contentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ContentInfo: %v", err)
	}

	if !contentInfo.ContentType.Equal(OIDEnvelopedData) {
		return nil, fmt.Errorf("not an EnvelopedData structure")
	}

	// Parse EnvelopedData
	var envelopedData CMSEnvelopedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &envelopedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal EnvelopedData: %v", err)
	}

	// Decrypt using RSA private key
	rsaPrivKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPrivKey, envelopedData.EncryptedContentInfo.EncryptedContent)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return decryptedData, nil
}

// PKInitDeriveKey derives the AS reply key from DH shared secret using PKINIT KDF
// As specified in RFC 4556 Section 3.2.3.1
func PKInitDeriveKey(sharedSecret, clientNonce, serverNonce []byte, etypeID int32) (types.EncryptionKey, error) {
	et, err := GetEtype(etypeID)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("unsupported etype: %v", err)
	}

	keySize := et.GetKeyByteSize()

	// RFC 4556 Section 3.2.3.1: Concatenate shared secret || client nonce || server nonce
	combined := append(sharedSecret, clientNonce...)
	combined = append(combined, serverNonce...)

	// RFC 4556: octetstring2key(x) == random-to-key(K-truncate(SHA1(0x00 | x) | SHA1(0x01 | x) | ...))
	// The counter is a SINGLE BYTE prepended to the input, not appended
	keyData := make([]byte, 0, keySize)
	rounds := (keySize + sha1.Size - 1) / sha1.Size // Calculate number of SHA1 rounds needed

	for i := 0; i < rounds; i++ {
		h := sha1.New()
		// Prepend single-byte counter as specified in RFC 4556
		h.Write([]byte{byte(i)})
		h.Write(combined)
		keyData = append(keyData, h.Sum(nil)...)
	}

	// Truncate to required key size
	keyData = keyData[:keySize]

	// Apply the etype's random-to-key function
	// This is required by RFC 4556 Section 3.2.3.1
	keyValue := et.RandomToKey(keyData)

	key := types.EncryptionKey{
		KeyType:  etypeID,
		KeyValue: keyValue,
	}

	return key, nil
}

// ComputeKDCReqBodyChecksum computes SHA1 checksum of AS-REQ body for PKINIT
func ComputeKDCReqBodyChecksum(kdcReqBodyBytes []byte) []byte {
	h := sha1.New()
	h.Write(kdcReqBodyBytes)
	return h.Sum(nil)
}
