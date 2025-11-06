package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a test certificate
func createTestCertificate(t *testing.T, isKDC bool) (*x509.Certificate, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err, "Failed to generate serial number")

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	if isKDC {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"kdc.example.com"}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err, "Failed to create certificate")

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err, "Failed to parse certificate")

	return cert, privateKey
}

func TestPKInitDeriveKey(t *testing.T) {
	t.Parallel()

	sharedSecret := make([]byte, 128) // 1024-bit shared secret
	for i := range sharedSecret {
		sharedSecret[i] = byte(i % 256)
	}
	clientNonce := []byte{0x01, 0x02, 0x03, 0x04}
	serverNonce := []byte{0x05, 0x06, 0x07, 0x08}

	tests := []struct {
		name      string
		etypeID   int32
		keySize   int
		expectErr bool
	}{
		{
			name:      "AES128-CTS-HMAC-SHA1-96",
			etypeID:   17,
			keySize:   16,
			expectErr: false,
		},
		{
			name:      "AES256-CTS-HMAC-SHA1-96",
			etypeID:   18,
			keySize:   32,
			expectErr: false,
		},
		{
			name:      "Unsupported etype",
			etypeID:   999,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := PKInitDeriveKey(sharedSecret, clientNonce, serverNonce, tt.etypeID)

			if tt.expectErr {
				assert.Error(t, err, "Expected error for unsupported etype")
				return
			}

			require.NoError(t, err, "PKInitDeriveKey should not return error")
			assert.Equal(t, tt.etypeID, key.KeyType, "Key type should match")
			assert.Len(t, key.KeyValue, tt.keySize, "Key size mismatch")

			// Derive again with same inputs should produce same key
			key2, err := PKInitDeriveKey(sharedSecret, clientNonce, serverNonce, tt.etypeID)
			require.NoError(t, err, "Second derivation should not return error")
			assert.Equal(t, key.KeyValue, key2.KeyValue, "Keys should be identical with same inputs")
		})
	}
}

func TestPKInitDeriveKey_RFC4556KDF(t *testing.T) {
	t.Parallel()

	// Test the RFC 4556 KDF formula: octetstring2key(x) = random-to-key(K-truncate(SHA1(0x00 | x) | SHA1(0x01 | x) | ...))
	// The counter is prepended as a single byte

	input := []byte("test input")
	etypeID := int32(18) // AES256

	key, err := PKInitDeriveKey(input, nil, nil, etypeID)
	require.NoError(t, err, "PKInitDeriveKey should not return error")

	// Manually compute first round: SHA1(0x00 | input)
	h := sha1.New()
	h.Write([]byte{0x00})
	h.Write(input)
	round0 := h.Sum(nil)

	// Manually compute second round: SHA1(0x01 | input)
	h = sha1.New()
	h.Write([]byte{0x01})
	h.Write(input)
	round1 := h.Sum(nil)

	// Combine and truncate to 32 bytes (AES256 key size)
	expectedKeyMaterial := append(round0, round1...)[:32]

	assert.Equal(t, expectedKeyMaterial, key.KeyValue, "Key derivation should follow RFC 4556 formula")
}

func TestPKInitDeriveKey_NonceOrder(t *testing.T) {
	t.Parallel()

	// Test that nonce order matters: shared_secret || client_nonce || server_nonce
	sharedSecret := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	clientNonce := []byte{0x11, 0x22, 0x33, 0x44}
	serverNonce := []byte{0x55, 0x66, 0x77, 0x88}
	etypeID := int32(18)

	key1, err := PKInitDeriveKey(sharedSecret, clientNonce, serverNonce, etypeID)
	require.NoError(t, err, "First derivation should not return error")

	// Swap nonces - should produce different key
	key2, err := PKInitDeriveKey(sharedSecret, serverNonce, clientNonce, etypeID)
	require.NoError(t, err, "Second derivation should not return error")

	assert.NotEqual(t, key1.KeyValue, key2.KeyValue, "Swapped nonces should produce different keys")
}

func TestComputeKDCReqBodyChecksum(t *testing.T) {
	t.Parallel()

	testData := []byte("test KDC-REQ-BODY data")

	checksum := ComputeKDCReqBodyChecksum(testData)

	// Verify it's a SHA1 hash
	assert.Len(t, checksum, sha1.Size, "Checksum should be SHA1 size (20 bytes)")

	// Compute expected SHA1
	h := sha1.New()
	h.Write(testData)
	expected := h.Sum(nil)

	assert.Equal(t, expected, checksum, "Checksum should match SHA1 hash")

	// Same input should produce same checksum
	checksum2 := ComputeKDCReqBodyChecksum(testData)
	assert.Equal(t, checksum, checksum2, "Checksums should be identical for same input")
}

func TestCreateCMSSignedData(t *testing.T) {
	t.Parallel()

	// Create test certificate and key
	cert, privateKey := createTestCertificate(t, false)

	// Test data to sign
	data := []byte("test authentication data")

	// Create CMS SignedData
	signedData, err := CreateCMSSignedData(data, cert, privateKey, nil)
	require.NoError(t, err, "CreateCMSSignedData should not return error")
	assert.NotEmpty(t, signedData, "SignedData should not be empty")

	// Parse the ContentInfo
	var contentInfo CMSContentInfo
	_, err = asn1.Unmarshal(signedData, &contentInfo)
	require.NoError(t, err, "Failed to unmarshal ContentInfo")

	// Verify ContentType is SignedData
	assert.True(t, contentInfo.ContentType.Equal(OIDSignedData), "ContentType should be SignedData")

	// Verify structure
	assert.NotEmpty(t, contentInfo.Content.Bytes, "Content should not be empty")
}

func TestVerifyCMSSignedData(t *testing.T) {
	t.Parallel()

	// Create test certificate and key
	cert, privateKey := createTestCertificate(t, false)

	// Test data to sign
	originalData := []byte("test authentication data")

	// Create CMS SignedData
	signedData, err := CreateCMSSignedData(originalData, cert, privateKey, nil)
	require.NoError(t, err, "Failed to create SignedData")

	// Verify SignedData
	extractedData, certs, err := VerifyCMSSignedData(signedData, nil)
	require.NoError(t, err, "VerifyCMSSignedData should not return error")

	// Verify extracted data matches original
	assert.Equal(t, originalData, extractedData, "Extracted data should match original")

	// Verify certificates
	assert.Len(t, certs, 1, "Should have one certificate")
	assert.Equal(t, cert.SerialNumber, certs[0].SerialNumber, "Certificate serial should match")
}

func TestVerifyCMSSignedData_TamperedData(t *testing.T) {
	t.Parallel()

	// Create test certificate and key
	cert, privateKey := createTestCertificate(t, false)

	// Test data to sign
	originalData := []byte("test authentication data")

	// Create CMS SignedData
	signedData, err := CreateCMSSignedData(originalData, cert, privateKey, nil)
	require.NoError(t, err, "Failed to create SignedData")

	// Tamper with the structure by corrupting ASN.1 encoding
	signedData[5] ^= 0xFF

	// Should fail to parse due to invalid ASN.1
	_, _, err = VerifyCMSSignedData(signedData, nil)
	assert.Error(t, err, "Verification should fail for corrupted ASN.1 structure")
}

func TestOIDConstants(t *testing.T) {
	t.Parallel()

	// Test that OID constants are defined correctly
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{"OIDPKInit", OIDPKInit},
		{"OIDPKInitAuthData", OIDPKInitAuthData},
		{"OIDPKInitDHKeyData", OIDPKInitDHKeyData},
		{"OIDPKInitRKeyData", OIDPKInitRKeyData},
		{"OIDDiffieHellman", OIDDiffieHellman},
		{"OIDSignedData", OIDSignedData},
		{"OIDSHA1WithRSA", OIDSHA1WithRSA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, tt.oid, "%s should not be empty", tt.name)
			assert.True(t, len(tt.oid) > 0, "%s should have at least one component", tt.name)
		})
	}
}

func TestCMSSignedData_RoundTrip(t *testing.T) {
	t.Parallel()

	// Create test certificate chain
	cert1, key1 := createTestCertificate(t, false)
	cert2, _ := createTestCertificate(t, false)

	certs := []*x509.Certificate{cert2} // Additional certs besides cert1
	data := []byte("test data for round trip")

	// Create SignedData with cert1 as primary and cert2 as additional
	signedData, err := CreateCMSSignedData(data, cert1, key1, certs)
	require.NoError(t, err, "Failed to create SignedData")

	// Verify SignedData
	extractedData, extractedCerts, err := VerifyCMSSignedData(signedData, nil)
	require.NoError(t, err, "Failed to verify SignedData")

	// Verify data matches
	assert.Equal(t, data, extractedData, "Data should match after round trip")

	// Verify all certificates are present
	assert.Len(t, extractedCerts, 2, "Should have two certificates")
	serialNumbers := []string{
		extractedCerts[0].SerialNumber.String(),
		extractedCerts[1].SerialNumber.String(),
	}
	assert.Contains(t, serialNumbers, cert1.SerialNumber.String(), "Should contain cert1")
	assert.Contains(t, serialNumbers, cert2.SerialNumber.String(), "Should contain cert2")
}

func TestCreateCMSSignedData_WithAttributes(t *testing.T) {
	t.Parallel()

	cert, privateKey := createTestCertificate(t, false)
	data := []byte("test data")

	signedData, err := CreateCMSSignedData(data, cert, privateKey, nil)
	require.NoError(t, err, "Failed to create SignedData")

	// Parse and verify the SignedData contains authenticated attributes
	var contentInfo CMSContentInfo
	_, err = asn1.Unmarshal(signedData, &contentInfo)
	require.NoError(t, err, "Failed to unmarshal ContentInfo")

	var parsedSignedData CMSSignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &parsedSignedData)
	require.NoError(t, err, "Failed to unmarshal SignedData")

	assert.NotEmpty(t, parsedSignedData.SignerInfos, "Should have signer infos")
	assert.NotEmpty(t, parsedSignedData.SignerInfos[0].SignedAttrs, "Should have authenticated attributes")
}

func TestPKInitDeriveKey_EmptyNonces(t *testing.T) {
	t.Parallel()

	sharedSecret := []byte{0x01, 0x02, 0x03, 0x04}
	etypeID := int32(18)

	// Test with nil nonces
	key1, err := PKInitDeriveKey(sharedSecret, nil, nil, etypeID)
	require.NoError(t, err, "Should handle nil nonces")
	assert.NotEmpty(t, key1.KeyValue, "Should derive key with nil nonces")

	// Test with empty nonces
	key2, err := PKInitDeriveKey(sharedSecret, []byte{}, []byte{}, etypeID)
	require.NoError(t, err, "Should handle empty nonces")

	// Both should produce the same result
	assert.Equal(t, key1.KeyValue, key2.KeyValue, "Nil and empty nonces should produce same result")
}

func TestCMSContentInfo_TagEncoding(t *testing.T) {
	t.Parallel()

	// Test that ContentInfo uses proper context-specific [0] EXPLICIT tagging
	cert, privateKey := createTestCertificate(t, false)
	data := []byte("test")

	signedData, err := CreateCMSSignedData(data, cert, privateKey, nil)
	require.NoError(t, err, "Failed to create SignedData")

	// Parse ContentInfo manually to verify tag structure
	var contentInfo CMSContentInfo
	rest, err := asn1.Unmarshal(signedData, &contentInfo)
	require.NoError(t, err, "Failed to unmarshal ContentInfo")
	assert.Empty(t, rest, "Should consume all bytes")

	// Verify Content has context-specific class
	assert.Equal(t, asn1.ClassContextSpecific, contentInfo.Content.Class, "Content should have context-specific class")
	assert.Equal(t, 0, contentInfo.Content.Tag, "Content should have tag 0")
	assert.True(t, contentInfo.Content.IsCompound, "Content should be compound (EXPLICIT)")
}

func TestSignerInfo_Structure(t *testing.T) {
	t.Parallel()

	cert, privateKey := createTestCertificate(t, false)
	data := []byte("test data")

	signedData, err := CreateCMSSignedData(data, cert, privateKey, nil)
	require.NoError(t, err, "Failed to create SignedData")

	// Parse and verify SignerInfo structure
	var contentInfo CMSContentInfo
	_, err = asn1.Unmarshal(signedData, &contentInfo)
	require.NoError(t, err, "Failed to unmarshal ContentInfo")

	var parsedSignedData CMSSignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &parsedSignedData)
	require.NoError(t, err, "Failed to unmarshal SignedData")

	require.Len(t, parsedSignedData.SignerInfos, 1, "Should have one SignerInfo")
	signerInfo := parsedSignedData.SignerInfos[0]

	// Verify SignerInfo fields
	assert.Equal(t, 1, signerInfo.Version, "SignerInfo version should be 1")
	assert.NotEmpty(t, signerInfo.Signature, "Signature should not be empty")
	assert.NotEmpty(t, signerInfo.SignedAttrs, "Authenticated attributes should not be empty")

	// Verify digest algorithm is SHA1 (OID 1.3.14.3.2.26)
	sha1OID := asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	assert.True(t, signerInfo.DigestAlgorithm.Algorithm.Equal(sha1OID), "Digest algorithm should be SHA1")

	// Verify signature algorithm is SHA1WithRSA
	assert.True(t, signerInfo.SignatureAlgorithm.Algorithm.Equal(OIDSHA1WithRSA), "Signature algorithm should be SHA1WithRSA")
}

func TestDecrypter_Interface(t *testing.T) {
	t.Parallel()

	// Verify that *rsa.PrivateKey implements crypto.Decrypter
	_, privateKey := createTestCertificate(t, false)

	var _ crypto.Decrypter = privateKey
	assert.NotNil(t, privateKey, "Private key should implement crypto.Decrypter")
}
