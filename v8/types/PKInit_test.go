package types

import (
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPKAuthenticator_MarshalUnmarshal(t *testing.T) {
	t.Parallel()

	testTime := time.Date(2024, 11, 6, 12, 0, 0, 0, time.UTC)
	paChecksum := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	original := PKAuthenticator{
		Cusec:      123456,
		Ctime:      testTime,
		Nonce:      987654321,
		PAChecksum: paChecksum,
	}

	// Marshal
	data, err := original.Marshal()
	require.NoError(t, err, "Failed to marshal PKAuthenticator")
	assert.NotEmpty(t, data, "Marshaled data should not be empty")

	// Unmarshal
	var unmarshaled PKAuthenticator
	err = unmarshaled.Unmarshal(data)
	require.NoError(t, err, "Failed to unmarshal PKAuthenticator")

	// Verify
	assert.Equal(t, original.Cusec, unmarshaled.Cusec, "Cusec mismatch")
	assert.Equal(t, original.Ctime.Unix(), unmarshaled.Ctime.Unix(), "Ctime mismatch")
	assert.Equal(t, original.Nonce, unmarshaled.Nonce, "Nonce mismatch")
	assert.Equal(t, original.PAChecksum, unmarshaled.PAChecksum, "PAChecksum mismatch")
}

func TestPKAuthenticator_OptionalChecksum(t *testing.T) {
	t.Parallel()

	testTime := time.Date(2024, 11, 6, 12, 0, 0, 0, time.UTC)

	original := PKAuthenticator{
		Cusec: 123456,
		Ctime: testTime,
		Nonce: 987654321,
		// PAChecksum is nil (optional)
	}

	// Marshal
	data, err := original.Marshal()
	require.NoError(t, err, "Failed to marshal PKAuthenticator without checksum")

	// Unmarshal
	var unmarshaled PKAuthenticator
	err = unmarshaled.Unmarshal(data)
	require.NoError(t, err, "Failed to unmarshal PKAuthenticator without checksum")

	// Verify
	assert.Equal(t, original.Cusec, unmarshaled.Cusec, "Cusec mismatch")
	assert.Equal(t, original.Nonce, unmarshaled.Nonce, "Nonce mismatch")
	assert.Nil(t, unmarshaled.PAChecksum, "PAChecksum should be nil")
}

func TestNewPKAuthenticator(t *testing.T) {
	t.Parallel()

	nonce := 123456789
	paChecksum := []byte{0x01, 0x02, 0x03, 0x04}

	before := time.Now().UTC()
	pka := NewPKAuthenticator(nonce, paChecksum)
	after := time.Now().UTC()

	assert.Equal(t, nonce, pka.Nonce, "Nonce should match")
	assert.Equal(t, paChecksum, pka.PAChecksum, "PAChecksum should match")
	assert.True(t, pka.Ctime.After(before) || pka.Ctime.Equal(before), "Ctime should be >= before")
	assert.True(t, pka.Ctime.Before(after) || pka.Ctime.Equal(after), "Ctime should be <= after")
	assert.GreaterOrEqual(t, pka.Cusec, 0, "Cusec should be non-negative")
	assert.LessOrEqual(t, pka.Cusec, 999999, "Cusec should be <= 999999")
}

func TestAuthPack_MarshalUnmarshal(t *testing.T) {
	t.Parallel()

	testTime := time.Date(2024, 11, 6, 12, 0, 0, 0, time.UTC)
	pka := PKAuthenticator{
		Cusec:      123456,
		Ctime:      testTime,
		Nonce:      987654321,
		PAChecksum: []byte{0x01, 0x02, 0x03},
	}

	spki := SubjectPublicKeyInfo{
		Algorithm: AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, // RSA
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     []byte{0x01, 0x02, 0x03, 0x04},
			BitLength: 32,
		},
	}

	original := AuthPack{
		PKAuthenticator:   pka,
		ClientPublicValue: spki,
		ClientDHNonce:     []byte{0xAA, 0xBB, 0xCC, 0xDD},
	}

	// Marshal
	data, err := original.Marshal()
	require.NoError(t, err, "Failed to marshal AuthPack")
	assert.NotEmpty(t, data, "Marshaled data should not be empty")

	// Unmarshal
	var unmarshaled AuthPack
	err = unmarshaled.Unmarshal(data)
	require.NoError(t, err, "Failed to unmarshal AuthPack")

	// Verify
	assert.Equal(t, original.PKAuthenticator.Nonce, unmarshaled.PKAuthenticator.Nonce, "Nonce mismatch")
	assert.Equal(t, original.ClientDHNonce, unmarshaled.ClientDHNonce, "ClientDHNonce mismatch")
	assert.Equal(t, original.ClientPublicValue.Algorithm.Algorithm, unmarshaled.ClientPublicValue.Algorithm.Algorithm, "Algorithm OID mismatch")
}

func TestPAPKASReq_MarshalUnmarshal(t *testing.T) {
	t.Parallel()

	original := PAPKASReq{
		SignedAuthPack: []byte{0x30, 0x82, 0x01, 0x23}, // Fake CMS data
		// Optional fields omitted
	}

	// Marshal
	data, err := original.Marshal()
	require.NoError(t, err, "Failed to marshal PAPKASReq")
	assert.NotEmpty(t, data, "Marshaled data should not be empty")

	// Unmarshal
	var unmarshaled PAPKASReq
	err = unmarshaled.Unmarshal(data)
	require.NoError(t, err, "Failed to unmarshal PAPKASReq")

	// Verify
	assert.Equal(t, original.SignedAuthPack, unmarshaled.SignedAuthPack, "SignedAuthPack mismatch")
}

func TestDHRepInfo_MarshalUnmarshal(t *testing.T) {
	t.Parallel()

	original := DHRepInfo{
		DHSignedData:  []byte{0x30, 0x82, 0x01, 0x23}, // Fake CMS signed data
		ServerDHNonce: []byte{0x11, 0x22, 0x33, 0x44},
	}

	// Marshal
	data, err := original.Marshal()
	require.NoError(t, err, "Failed to marshal DHRepInfo")
	assert.NotEmpty(t, data, "Marshaled data should not be empty")

	// Unmarshal
	var unmarshaled DHRepInfo
	err = unmarshaled.Unmarshal(data)
	require.NoError(t, err, "Failed to unmarshal DHRepInfo")

	// Verify
	assert.Equal(t, original.DHSignedData, unmarshaled.DHSignedData, "DHSignedData mismatch")
	assert.Equal(t, original.ServerDHNonce, unmarshaled.ServerDHNonce, "ServerDHNonce mismatch")
}

func TestKDCDHKeyInfo_MarshalUnmarshal(t *testing.T) {
	t.Parallel()

	testTime := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)
	pubKey := asn1.BitString{
		Bytes:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		BitLength: 40,
	}

	original := KDCDHKeyInfo{
		SubjectPublicKey: pubKey,
		Nonce:            123456789,
		DHKeyExpiration:  testTime,
	}

	// Marshal
	data, err := original.Marshal()
	require.NoError(t, err, "Failed to marshal KDCDHKeyInfo")
	assert.NotEmpty(t, data, "Marshaled data should not be empty")

	// Unmarshal
	var unmarshaled KDCDHKeyInfo
	err = unmarshaled.Unmarshal(data)
	require.NoError(t, err, "Failed to unmarshal KDCDHKeyInfo")

	// Verify
	assert.Equal(t, original.SubjectPublicKey.Bytes, unmarshaled.SubjectPublicKey.Bytes, "SubjectPublicKey bytes mismatch")
	assert.Equal(t, original.SubjectPublicKey.BitLength, unmarshaled.SubjectPublicKey.BitLength, "SubjectPublicKey bit length mismatch")
	assert.Equal(t, original.Nonce, unmarshaled.Nonce, "Nonce mismatch")
	assert.Equal(t, original.DHKeyExpiration.Unix(), unmarshaled.DHKeyExpiration.Unix(), "DHKeyExpiration mismatch")
}

func TestReplyKeyPack_MarshalUnmarshal(t *testing.T) {
	t.Parallel()

	original := ReplyKeyPack{
		ReplyKey: EncryptionKey{
			KeyType:  18, // AES256-CTS-HMAC-SHA1-96
			KeyValue: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		},
		ASChecksum: Checksum{
			CksumType: 16,
			Checksum:  []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
	}

	// Marshal
	data, err := original.Marshal()
	require.NoError(t, err, "Failed to marshal ReplyKeyPack")
	assert.NotEmpty(t, data, "Marshaled data should not be empty")

	// Unmarshal
	var unmarshaled ReplyKeyPack
	err = unmarshaled.Unmarshal(data)
	require.NoError(t, err, "Failed to unmarshal ReplyKeyPack")

	// Verify
	assert.Equal(t, original.ReplyKey.KeyType, unmarshaled.ReplyKey.KeyType, "ReplyKey KeyType mismatch")
	assert.Equal(t, original.ReplyKey.KeyValue, unmarshaled.ReplyKey.KeyValue, "ReplyKey KeyValue mismatch")
	assert.Equal(t, original.ASChecksum.CksumType, unmarshaled.ASChecksum.CksumType, "ASChecksum CksumType mismatch")
	assert.Equal(t, original.ASChecksum.Checksum, unmarshaled.ASChecksum.Checksum, "ASChecksum Checksum mismatch")
}

func TestPAData_GetPAPKASReq(t *testing.T) {
	t.Parallel()

	paPKAsReq := PAPKASReq{
		SignedAuthPack: []byte{0x30, 0x82, 0x01, 0x23},
	}
	data, err := paPKAsReq.Marshal()
	require.NoError(t, err, "Failed to marshal PAPKASReq")

	paData := PAData{
		PADataType:  patype.PA_PK_AS_REQ,
		PADataValue: data,
	}

	// Test success case
	result, err := paData.GetPAPKASReq()
	require.NoError(t, err, "GetPAPKASReq should succeed")
	assert.Equal(t, paPKAsReq.SignedAuthPack, result.SignedAuthPack, "SignedAuthPack should match")

	// Test wrong type case
	paData.PADataType = patype.PA_TGS_REQ
	_, err = paData.GetPAPKASReq()
	assert.Error(t, err, "GetPAPKASReq should fail with wrong PAData type")
	assert.Contains(t, err.Error(), "does not contain PA-PK-AS-REQ data", "Error message should indicate wrong type")
}

func TestPAData_GetPAPKASRep(t *testing.T) {
	t.Parallel()

	// PAPKASRep is a CHOICE type that's handled as a RawValue
	// The actual parsing is complex and tested in integration tests
	// Here we just test the error case for wrong PAData type

	paData := PAData{
		PADataType:  patype.PA_TGS_REQ, // Wrong type
		PADataValue: []byte{0x30, 0x10}, // Dummy data
	}

	// Test wrong type case
	_, err := paData.GetPAPKASRep()
	assert.Error(t, err, "GetPAPKASRep should fail with wrong PAData type")
	assert.Contains(t, err.Error(), "does not contain PA-PK-AS-REP data", "Error message should indicate wrong type")

	// Test with correct type but verify it attempts to unmarshal
	paData.PADataType = patype.PA_PK_AS_REP
	result, err := paData.GetPAPKASRep()
	// May fail or succeed depending on data format, but should attempt unmarshaling
	// We're just verifying the type check works correctly
	if err == nil {
		assert.NotNil(t, result, "Result should not be nil on success")
	}
}

func TestSubjectPublicKeyInfo_MarshalUnmarshal(t *testing.T) {
	t.Parallel()

	// Test with RSA algorithm
	original := SubjectPublicKeyInfo{
		Algorithm: AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, // RSA
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     []byte{0x00, 0x01, 0x02, 0x03, 0x04},
			BitLength: 40,
		},
	}

	// Marshal using standard ASN.1
	data, err := asn1.Marshal(original)
	require.NoError(t, err, "Failed to marshal SubjectPublicKeyInfo")
	assert.NotEmpty(t, data, "Marshaled data should not be empty")

	// Unmarshal
	var unmarshaled SubjectPublicKeyInfo
	_, err = asn1.Unmarshal(data, &unmarshaled)
	require.NoError(t, err, "Failed to unmarshal SubjectPublicKeyInfo")

	// Verify
	assert.Equal(t, original.Algorithm.Algorithm, unmarshaled.Algorithm.Algorithm, "Algorithm OID mismatch")
	assert.Equal(t, original.SubjectPublicKey.Bytes, unmarshaled.SubjectPublicKey.Bytes, "SubjectPublicKey bytes mismatch")
	assert.Equal(t, original.SubjectPublicKey.BitLength, unmarshaled.SubjectPublicKey.BitLength, "SubjectPublicKey bit length mismatch")
}

func TestAlgorithmIdentifier_WithParameters(t *testing.T) {
	t.Parallel()

	// Create DH domain parameters
	type DHParams struct {
		P *big.Int
		G *big.Int
		Q *big.Int
	}

	params := DHParams{
		P: big.NewInt(12345),
		G: big.NewInt(2),
		Q: big.NewInt(0),
	}

	paramsBytes, err := asn1.Marshal(params)
	require.NoError(t, err, "Failed to marshal DH parameters")

	original := AlgorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}, // DH
		Parameters: asn1.RawValue{FullBytes: paramsBytes},
	}

	// Marshal
	data, err := asn1.Marshal(original)
	require.NoError(t, err, "Failed to marshal AlgorithmIdentifier")

	// Unmarshal
	var unmarshaled AlgorithmIdentifier
	_, err = asn1.Unmarshal(data, &unmarshaled)
	require.NoError(t, err, "Failed to unmarshal AlgorithmIdentifier")

	// Verify
	assert.Equal(t, original.Algorithm, unmarshaled.Algorithm, "Algorithm OID mismatch")
	assert.Equal(t, original.Parameters.FullBytes, unmarshaled.Parameters.FullBytes, "Parameters mismatch")
}

