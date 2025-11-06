package crypto

import (
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDHParameters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		group     DHGroup
		expectErr bool
		groupID   int
		primeBits int
	}{
		{
			name:      "MODP Group 2",
			group:     DHGroupModP2,
			expectErr: false,
			groupID:   2,
			primeBits: 1024,
		},
		{
			name:      "MODP Group 14",
			group:     DHGroupModP14,
			expectErr: false,
			groupID:   14,
			primeBits: 2048,
		},
		{
			name:      "Invalid group",
			group:     DHGroup(999),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := GetDHParameters(tt.group)

			if tt.expectErr {
				assert.Error(t, err, "Expected error for invalid group")
				return
			}

			require.NoError(t, err, "GetDHParameters should not return error")
			assert.Equal(t, tt.groupID, params.GroupID, "GroupID mismatch")
			assert.Equal(t, tt.primeBits, params.Prime.BitLen(), "Prime bit length mismatch")
			assert.Equal(t, int64(2), params.Generator.Int64(), "Generator should be 2")
			assert.True(t, params.Prime.ProbablyPrime(20), "Prime should be prime")
		})
	}
}

func TestGenerateDHKeyPair(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		group DHGroup
	}{
		{"MODP Group 2", DHGroupModP2},
		{"MODP Group 14", DHGroupModP14},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := GenerateDHKeyPair(tt.group)
			require.NoError(t, err, "GenerateDHKeyPair should not return error")
			assert.NotNil(t, keyPair, "KeyPair should not be nil")

			// Verify private key is in valid range [2, prime-2]
			assert.True(t, keyPair.PrivateKey.Cmp(big.NewInt(2)) >= 0, "Private key should be >= 2")
			maxPrivate := new(big.Int).Sub(keyPair.Parameters.Prime, big.NewInt(1))
			assert.True(t, keyPair.PrivateKey.Cmp(maxPrivate) < 0, "Private key should be < prime-1")

			// Verify public key is in valid range [2, prime-1]
			assert.True(t, keyPair.PublicKey.Cmp(big.NewInt(1)) > 0, "Public key should be > 1")
			assert.True(t, keyPair.PublicKey.Cmp(keyPair.Parameters.Prime) < 0, "Public key should be < prime")

			// Verify public key = g^privateKey mod p
			expectedPubKey := new(big.Int).Exp(
				keyPair.Parameters.Generator,
				keyPair.PrivateKey,
				keyPair.Parameters.Prime,
			)
			assert.Equal(t, 0, expectedPubKey.Cmp(keyPair.PublicKey), "Public key computation mismatch")
		})
	}
}

func TestDHKeyPair_ComputeSharedSecret(t *testing.T) {
	t.Parallel()

	// Generate two key pairs
	alice, err := GenerateDHKeyPair(DHGroupModP2)
	require.NoError(t, err, "Failed to generate Alice's key pair")

	bob, err := GenerateDHKeyPair(DHGroupModP2)
	require.NoError(t, err, "Failed to generate Bob's key pair")

	// Alice computes shared secret using Bob's public key
	aliceShared, err := alice.ComputeSharedSecret(bob.PublicKey)
	require.NoError(t, err, "Alice failed to compute shared secret")

	// Bob computes shared secret using Alice's public key
	bobShared, err := bob.ComputeSharedSecret(alice.PublicKey)
	require.NoError(t, err, "Bob failed to compute shared secret")

	// Shared secrets should match
	assert.Equal(t, 0, aliceShared.Cmp(bobShared), "Shared secrets should match")
	assert.True(t, aliceShared.Cmp(big.NewInt(0)) > 0, "Shared secret should be positive")
}

func TestDHKeyPair_ComputeSharedSecret_InvalidPeerKey(t *testing.T) {
	t.Parallel()

	keyPair, err := GenerateDHKeyPair(DHGroupModP2)
	require.NoError(t, err, "Failed to generate key pair")

	tests := []struct {
		name      string
		peerKey   *big.Int
		expectErr bool
	}{
		{
			name:      "Valid peer key",
			peerKey:   big.NewInt(1234567890),
			expectErr: false,
		},
		{
			name:      "Peer key is 0",
			peerKey:   big.NewInt(0),
			expectErr: true,
		},
		{
			name:      "Peer key is 1",
			peerKey:   big.NewInt(1),
			expectErr: true,
		},
		{
			name:      "Peer key >= prime",
			peerKey:   new(big.Int).Add(keyPair.Parameters.Prime, big.NewInt(1)),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := keyPair.ComputeSharedSecret(tt.peerKey)
			if tt.expectErr {
				assert.Error(t, err, "Expected error for invalid peer key")
			} else {
				assert.NoError(t, err, "Should not error for valid peer key")
			}
		})
	}
}

func TestEncodeDHPublicKey(t *testing.T) {
	t.Parallel()

	keyPair, err := GenerateDHKeyPair(DHGroupModP2)
	require.NoError(t, err, "Failed to generate key pair")

	spki, err := EncodeDHPublicKey(keyPair.PublicKey, keyPair.Parameters)
	require.NoError(t, err, "EncodeDHPublicKey should not return error")

	// Verify algorithm OID is DH
	assert.True(t, spki.Algorithm.Algorithm.Equal(OIDDiffieHellman), "Algorithm OID should be DH")

	// Verify we can decode the parameters
	type DHParams struct {
		P *big.Int
		G *big.Int
		Q *big.Int
	}
	var params DHParams
	_, err = asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &params)
	require.NoError(t, err, "Failed to unmarshal DH parameters")

	assert.Equal(t, 0, params.P.Cmp(keyPair.Parameters.Prime), "Prime in parameters should match")
	assert.Equal(t, 0, params.G.Cmp(keyPair.Parameters.Generator), "Generator in parameters should match")

	// Verify we can decode the public key
	var pubKey *big.Int
	_, err = asn1.Unmarshal(spki.SubjectPublicKey.Bytes, &pubKey)
	require.NoError(t, err, "Failed to unmarshal public key")
	assert.Equal(t, 0, pubKey.Cmp(keyPair.PublicKey), "Public key should match")
}

func TestDecodeDHPublicKey(t *testing.T) {
	t.Parallel()

	// Generate and encode a key
	originalKeyPair, err := GenerateDHKeyPair(DHGroupModP2)
	require.NoError(t, err, "Failed to generate key pair")

	spki, err := EncodeDHPublicKey(originalKeyPair.PublicKey, originalKeyPair.Parameters)
	require.NoError(t, err, "Failed to encode DH public key")

	// Decode it
	decodedPubKey, decodedParams, err := DecodeDHPublicKey(spki)
	require.NoError(t, err, "DecodeDHPublicKey should not return error")

	// Verify decoded values match original
	assert.Equal(t, 0, decodedPubKey.Cmp(originalKeyPair.PublicKey), "Decoded public key should match original")
	assert.Equal(t, 0, decodedParams.Prime.Cmp(originalKeyPair.Parameters.Prime), "Decoded prime should match original")
	assert.Equal(t, 0, decodedParams.Generator.Cmp(originalKeyPair.Parameters.Generator), "Decoded generator should match original")
	assert.Equal(t, originalKeyPair.Parameters.GroupID, decodedParams.GroupID, "Decoded group ID should match original")
}

func TestDecodeDHPublicKey_WrongAlgorithm(t *testing.T) {
	t.Parallel()

	// Create SPKI with wrong algorithm (RSA instead of DH)
	spki := types.SubjectPublicKeyInfo{
		Algorithm: types.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, // RSA
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     []byte{0x01, 0x02, 0x03},
			BitLength: 24,
		},
	}

	_, _, err := DecodeDHPublicKey(spki)
	assert.Error(t, err, "Should error with wrong algorithm")
	assert.Contains(t, err.Error(), "not a Diffie-Hellman public key", "Error message should indicate wrong algorithm")
}

func TestGenerateDHNonce(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		size int
	}{
		{"32 bytes", 32},
		{"16 bytes", 16},
		{"64 bytes", 64},
		{"Default size", 0}, // Should use default of 32
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce, err := GenerateDHNonce(tt.size)
			require.NoError(t, err, "GenerateDHNonce should not return error")

			expectedSize := tt.size
			if expectedSize == 0 {
				expectedSize = 32 // default
			}
			assert.Len(t, nonce, expectedSize, "Nonce size mismatch")

			// Generate another nonce and verify they're different (with high probability)
			nonce2, err := GenerateDHNonce(tt.size)
			require.NoError(t, err, "Second GenerateDHNonce should not return error")
			assert.NotEqual(t, nonce, nonce2, "Two nonces should be different")
		})
	}
}

func TestPKInitDeriveKeyFromDH(t *testing.T) {
	t.Parallel()

	// Generate a shared secret
	alice, err := GenerateDHKeyPair(DHGroupModP2)
	require.NoError(t, err, "Failed to generate Alice's key pair")

	bob, err := GenerateDHKeyPair(DHGroupModP2)
	require.NoError(t, err, "Failed to generate Bob's key pair")

	sharedSecret, err := alice.ComputeSharedSecret(bob.PublicKey)
	require.NoError(t, err, "Failed to compute shared secret")

	clientNonce := []byte{0x01, 0x02, 0x03, 0x04}
	serverNonce := []byte{0x05, 0x06, 0x07, 0x08}
	etypeID := int32(18) // AES256-CTS-HMAC-SHA1-96

	// Calculate prime size for MODP Group 2
	primeSize := (alice.Parameters.Prime.BitLen() + 7) / 8

	// Derive key
	key, err := PKInitDeriveKeyFromDH(sharedSecret, clientNonce, serverNonce, etypeID, primeSize)
	require.NoError(t, err, "PKInitDeriveKeyFromDH should not return error")

	assert.Equal(t, etypeID, key.KeyType, "Key type should match")
	assert.NotEmpty(t, key.KeyValue, "Key value should not be empty")
	assert.Equal(t, 32, len(key.KeyValue), "AES256 key should be 32 bytes")

	// Derive again with same inputs should produce same key
	key2, err := PKInitDeriveKeyFromDH(sharedSecret, clientNonce, serverNonce, etypeID, primeSize)
	require.NoError(t, err, "Second PKInitDeriveKeyFromDH should not return error")
	assert.Equal(t, key.KeyValue, key2.KeyValue, "Keys should be identical with same inputs")

	// Different nonce should produce different key
	differentNonce := []byte{0xFF, 0xFE, 0xFD, 0xFC}
	key3, err := PKInitDeriveKeyFromDH(sharedSecret, differentNonce, serverNonce, etypeID, primeSize)
	require.NoError(t, err, "PKInitDeriveKeyFromDH with different nonce should not return error")
	assert.NotEqual(t, key.KeyValue, key3.KeyValue, "Keys should differ with different client nonce")
}

func TestValidateDHPublicKey(t *testing.T) {
	t.Parallel()

	params, err := GetDHParameters(DHGroupModP2)
	require.NoError(t, err, "Failed to get DH parameters")

	tests := []struct {
		name      string
		pubKey    *big.Int
		expectErr bool
	}{
		{
			name:      "Valid public key",
			pubKey:    big.NewInt(1234567890),
			expectErr: false,
		},
		{
			name:      "Public key is 0",
			pubKey:    big.NewInt(0),
			expectErr: true,
		},
		{
			name:      "Public key is 1",
			pubKey:    big.NewInt(1),
			expectErr: true,
		},
		{
			name:      "Public key is 2 (valid minimum)",
			pubKey:    big.NewInt(2),
			expectErr: false,
		},
		{
			name:      "Public key equals prime-2 (valid maximum)",
			pubKey:    new(big.Int).Sub(params.Prime, big.NewInt(2)),
			expectErr: false,
		},
		{
			name:      "Public key equals prime-1 (invalid)",
			pubKey:    new(big.Int).Sub(params.Prime, big.NewInt(1)),
			expectErr: true,
		},
		{
			name:      "Public key equals prime (invalid)",
			pubKey:    params.Prime,
			expectErr: true,
		},
		{
			name:      "Public key > prime",
			pubKey:    new(big.Int).Add(params.Prime, big.NewInt(1)),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDHPublicKey(tt.pubKey, params)
			if tt.expectErr {
				assert.Error(t, err, "Expected validation error")
			} else {
				assert.NoError(t, err, "Expected validation to pass")
			}
		})
	}
}

func TestCreateClientDHPublicValueFromKey(t *testing.T) {
	t.Parallel()

	// Use a specific private key value
	privateKey := big.NewInt(123456789)
	preferredGroup := DHGroupModP2

	keyPair, spki, clientNonce, err := CreateClientDHPublicValueFromKey(preferredGroup, privateKey)
	require.NoError(t, err, "CreateClientDHPublicValueFromKey should not return error")

	// Verify key pair uses the provided private key
	assert.NotNil(t, keyPair, "KeyPair should not be nil")
	assert.Equal(t, 0, keyPair.PrivateKey.Cmp(privateKey), "Private key should match input")

	// Verify public key is computed correctly: g^privateKey mod p
	params, err := GetDHParameters(preferredGroup)
	require.NoError(t, err, "Failed to get DH parameters")

	expectedPubKey := new(big.Int).Exp(params.Generator, privateKey, params.Prime)
	assert.Equal(t, 0, keyPair.PublicKey.Cmp(expectedPubKey), "Public key computation mismatch")

	// Verify SPKI
	decodedPubKey, _, err := DecodeDHPublicKey(spki)
	require.NoError(t, err, "Failed to decode generated SPKI")
	assert.Equal(t, 0, decodedPubKey.Cmp(keyPair.PublicKey), "Decoded public key should match")

	// Verify nonce
	assert.Len(t, clientNonce, 32, "Client nonce should be 32 bytes")
}

func TestDHSharedSecretPadding(t *testing.T) {
	t.Parallel()

	// Test that shared secret is properly padded to match prime size
	alice, err := GenerateDHKeyPair(DHGroupModP2)
	require.NoError(t, err, "Failed to generate Alice's key pair")

	// Use a small public key for Bob that will result in a smaller shared secret
	bobPrivateKey := big.NewInt(12345)
	bobPublicKey := new(big.Int).Exp(alice.Parameters.Generator, bobPrivateKey, alice.Parameters.Prime)

	sharedSecret, err := alice.ComputeSharedSecret(bobPublicKey)
	require.NoError(t, err, "Failed to compute shared secret")

	// Derive key
	clientNonce := []byte{0x01, 0x02, 0x03, 0x04}
	serverNonce := []byte{0x05, 0x06, 0x07, 0x08}
	etypeID := int32(18)
	primeSize := (alice.Parameters.Prime.BitLen() + 7) / 8

	key, err := PKInitDeriveKeyFromDH(sharedSecret, clientNonce, serverNonce, etypeID, primeSize)
	require.NoError(t, err, "PKInitDeriveKeyFromDH should not return error")
	assert.NotEmpty(t, key.KeyValue, "Key should be derived successfully")

	// The key derivation should work correctly even if shared secret is smaller than prime
	assert.Equal(t, 32, len(key.KeyValue), "AES256 key should be 32 bytes")
}
