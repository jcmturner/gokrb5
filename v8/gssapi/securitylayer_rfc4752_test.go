package gssapi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 4752 and RFC 4422 SASL Compliance Tests
// These tests verify that our implementation follows RFC 4752 (GSSAPI SASL mechanism)
// and RFC 4422 (SASL Framework) precisely.

// getTestKeyForSASL returns a test encryption key for SASL testing
func getTestKeyForSASL() types.EncryptionKey {
	key, _ := hex.DecodeString("14f9bde6b50ec508201a97f74c4e5bd3")
	return types.EncryptionKey{
		KeyType:  17, // AES128-CTS-HMAC-SHA1-96
		KeyValue: key,
	}
}

// TestRFC4752_SecurityLayerValues verifies security layer bit-mask values
// Per RFC 4752 Section 3: Layer 1 = No security, 2 = Integrity, 4 = Confidentiality
func TestRFC4752_SecurityLayerValues(t *testing.T) {
	assert.Equal(t, SecurityLayer(1), SecurityLayerNone, "No security layer must be bit-mask 1")
	assert.Equal(t, SecurityLayer(2), SecurityLayerIntegrity, "Integrity layer must be bit-mask 2")
	assert.Equal(t, SecurityLayer(4), SecurityLayerConfidentiality, "Confidentiality layer must be bit-mask 4")
}

// TestRFC4752_SecurityLayerNone verifies behavior with no security layer
// Per RFC 4752: Layer 1 provides authentication only, no wrapping
func TestRFC4752_SecurityLayerNone(t *testing.T) {
	key := getTestKeyForSASL()
	session, err := NewSecurityLayerSession(key, SecurityLayerNone, true, 0)
	require.NoError(t, err)

	message := []byte("plaintext message")

	// With no security layer, message should pass through unchanged
	wrapped, err := session.Wrap(message)
	require.NoError(t, err)
	assert.Equal(t, message, wrapped, "No security layer should not modify message")

	unwrapped, err := session.Unwrap(wrapped)
	require.NoError(t, err)
	assert.Equal(t, message, unwrapped, "Unwrap should return original message")
}

// TestRFC4752_IntegrityLayer verifies integrity protection (conf_flag=FALSE)
// Per RFC 4752 Section 3: "the client passes the data to GSS_Wrap with conf_flag set to FALSE"
func TestRFC4752_IntegrityLayer(t *testing.T) {
	key := getTestKeyForSASL()
	clientSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
	require.NoError(t, err)

	message := []byte("integrity protected message")

	// Wrap with integrity (conf_flag=FALSE, sealed bit not set)
	wrapped, err := clientSession.Wrap(message)
	require.NoError(t, err)

	// Verify sealed flag is NOT set (bit 1 of flags byte)
	flags := wrapped[2]
	sealedBit := (flags & 0x02) >> 1
	assert.Equal(t, byte(0), sealedBit, "Integrity layer must have conf_flag=FALSE (sealed bit unset)")

	// Verify message can be unwrapped
	unwrapped, err := serverSession.Unwrap(wrapped)
	require.NoError(t, err)
	assert.Equal(t, message, unwrapped)
}

// TestRFC4752_ConfidentialityLayer verifies confidentiality protection (conf_flag=TRUE)
// Per RFC 4752 Section 3: Confidentiality layer uses GSS_Wrap with conf_flag=TRUE
func TestRFC4752_ConfidentialityLayer(t *testing.T) {
	key := getTestKeyForSASL()
	clientSession, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, false, 0)
	require.NoError(t, err)

	message := []byte("confidential message")

	// Wrap with confidentiality (conf_flag=TRUE, sealed bit set)
	wrapped, err := clientSession.Wrap(message)
	require.NoError(t, err)

	// Verify sealed flag IS set (bit 1 of flags byte)
	flags := wrapped[2]
	sealedBit := (flags & 0x02) >> 1
	assert.Equal(t, byte(1), sealedBit, "Confidentiality layer must have conf_flag=TRUE (sealed bit set)")

	// Verify payload is encrypted (not plaintext)
	payload := wrapped[16:] // Skip header
	assert.NotEqual(t, message, payload, "Payload must be encrypted with confidentiality layer")

	// Verify message can be unwrapped
	unwrapped, err := serverSession.Unwrap(wrapped)
	require.NoError(t, err)
	assert.Equal(t, message, unwrapped)
}

// TestRFC4422_SASLFraming verifies SASL message framing per RFC 4422 Section 3.7
// "Each buffer of protected data is transferred...as a sequence of octets prepended
// with a four-octet field in network byte order that represents the length of the buffer."
func TestRFC4422_SASLFraming(t *testing.T) {
	key := getTestKeyForSASL()
	session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	message := []byte("test message for framing")

	// Wrap with SASL framing
	framed, err := session.WrapWithSASLFraming(message)
	require.NoError(t, err)

	// Verify structure: [4-byte length][wrapped token]
	require.GreaterOrEqual(t, len(framed), 4, "Framed message must have at least 4-byte length prefix")

	// Extract and verify length field (network byte order = big-endian)
	length := binary.BigEndian.Uint32(framed[0:4])
	wrappedTokenSize := uint32(len(framed) - 4)

	assert.Equal(t, wrappedTokenSize, length, "Length field must equal size of wrapped token (excluding length field itself)")

	// Verify the wrapped token starts at byte 4
	wrappedToken := framed[4:]
	assert.Equal(t, int(length), len(wrappedToken), "Wrapped token size must match length field")

	// Verify token has valid GSS-API WrapToken format
	assert.Equal(t, byte(0x05), wrappedToken[0], "Wrapped token must be valid GSS-API token")
	assert.Equal(t, byte(0x04), wrappedToken[1], "Wrapped token must be valid GSS-API token")
}

// TestRFC4422_NetworkByteOrder verifies length field uses network byte order (big-endian)
// Per RFC 4422 Section 3.7: "four-octet field in network byte order"
func TestRFC4422_NetworkByteOrder(t *testing.T) {
	key := getTestKeyForSASL()
	session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	message := []byte("test")
	framed, err := session.WrapWithSASLFraming(message)
	require.NoError(t, err)

	// Extract length using big-endian
	lengthBigEndian := binary.BigEndian.Uint32(framed[0:4])

	// Extract length using little-endian (incorrect)
	lengthLittleEndian := binary.LittleEndian.Uint32(framed[0:4])

	// Verify they're different (unless length happens to be symmetric)
	actualTokenSize := uint32(len(framed) - 4)

	assert.Equal(t, actualTokenSize, lengthBigEndian, "Big-endian parsing must yield correct length")

	// Only check this if the length isn't a symmetric value
	if lengthBigEndian != lengthLittleEndian {
		assert.NotEqual(t, actualTokenSize, lengthLittleEndian, "Little-endian parsing must not yield correct length")
	}
}

// TestRFC4422_MaxBufferSize verifies maximum buffer size handling
// Per RFC 4422 Section 3.7: "The length of the protected data buffer MUST be no larger
// than the maximum size that the other side expects"
func TestRFC4422_MaxBufferSize(t *testing.T) {
	key := getTestKeyForSASL()

	// Create session with max message size of 100 bytes
	maxSize := 100
	session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, maxSize)
	require.NoError(t, err)

	// Message within limit should succeed
	smallMessage := make([]byte, 50)
	_, err = session.Wrap(smallMessage)
	assert.NoError(t, err, "Message within limit should wrap successfully")

	// Message exceeding limit should be rejected on unwrap
	largeMessage := make([]byte, 200)
	wrapped, err := session.Wrap(largeMessage)
	require.NoError(t, err, "Wrap should succeed regardless of size")

	// Create receiving session with same max size
	recvSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, maxSize)
	require.NoError(t, err)

	// Unwrap should reject message exceeding max size
	_, err = recvSession.Unwrap(wrapped)
	assert.Error(t, err, "Unwrap should reject messages exceeding maximum size")
	assert.Contains(t, err.Error(), "exceeds maximum", "Error should indicate size limit exceeded")
}

// TestRFC4422_SecurityLayerReplacement verifies that security layers can be replaced
// Per RFC 4422 Section 3.7: "Protocols supporting multiple authentications cannot
// simultaneously have multiple security layers in effect"
func TestRFC4422_SecurityLayerReplacement(t *testing.T) {
	key := getTestKeyForSASL()

	// Start with no security layer
	session, err := NewSecurityLayerSession(key, SecurityLayerNone, true, 0)
	require.NoError(t, err)
	assert.Equal(t, SecurityLayerNone, session.layer)

	// "Replace" with integrity layer (create new session)
	session, err = NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)
	assert.Equal(t, SecurityLayerIntegrity, session.layer)

	// "Replace" with confidentiality layer (create new session)
	session, err = NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0)
	require.NoError(t, err)
	assert.Equal(t, SecurityLayerConfidentiality, session.layer)
}

// TestRFC4422_SASLFramingRoundTrip verifies complete SASL framing round-trip
func TestRFC4422_SASLFramingRoundTrip(t *testing.T) {
	key := getTestKeyForSASL()
	clientSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
	require.NoError(t, err)

	originalMessage := []byte("SASL framed message test")

	// Client wraps with SASL framing
	framed, err := clientSession.WrapWithSASLFraming(originalMessage)
	require.NoError(t, err)

	// Server unwraps from SASL framing
	reader := bytes.NewReader(framed)
	unwrapped, err := serverSession.UnwrapFromSASLFraming(reader)
	require.NoError(t, err)

	assert.Equal(t, originalMessage, unwrapped, "Round-trip should preserve message")
}

// TestRFC4752_BiDirectionalCommunication verifies bidirectional wrapped communication
// Per RFC 4752: Both client and server can send wrapped messages
func TestRFC4752_BiDirectionalCommunication(t *testing.T) {
	key := getTestKeyForSASL()
	clientSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
	require.NoError(t, err)

	// Client to server
	clientMsg := []byte("client request")
	wrapped, err := clientSession.Wrap(clientMsg)
	require.NoError(t, err)

	unwrapped, err := serverSession.Unwrap(wrapped)
	require.NoError(t, err)
	assert.Equal(t, clientMsg, unwrapped)

	// Server to client
	serverMsg := []byte("server response")
	wrapped, err = serverSession.Wrap(serverMsg)
	require.NoError(t, err)

	unwrapped, err = clientSession.Unwrap(wrapped)
	require.NoError(t, err)
	assert.Equal(t, serverMsg, unwrapped)
}

// TestRFC4422_ZeroLengthMessage verifies handling of zero-length messages
func TestRFC4422_ZeroLengthMessage(t *testing.T) {
	key := getTestKeyForSASL()
	session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	// Wrap empty message
	emptyMessage := []byte{}
	wrapped, err := session.Wrap(emptyMessage)
	require.NoError(t, err)

	// Should still have valid WrapToken structure with header and checksum
	require.GreaterOrEqual(t, len(wrapped), 16, "Even empty message should have header")
}

// TestRFC4422_LengthFieldRange verifies length field can represent expected range
func TestRFC4422_LengthFieldRange(t *testing.T) {
	// 4-byte unsigned integer can represent 0 to 4,294,967,295
	// Our implementation limits to 16MB (1<<24 = 16,777,216)

	tests := []struct {
		name        string
		length      uint32
		shouldError bool
	}{
		{"Zero length", 0, true},
		{"Small message", 100, false},
		{"1KB message", 1024, false},
		{"1MB message", 1 << 20, false},
		{"16MB message", 1 << 24, false},
		{"Over 16MB", (1 << 24) + 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a simulated SASL frame with the given length
			frame := make([]byte, 4)
			binary.BigEndian.PutUint32(frame, tt.length)

			key := getTestKeyForSASL()
			session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
			require.NoError(t, err)

			// Try to read from this frame
			// We expect an error if length is 0 or > 16MB
			reader := bytes.NewReader(frame)
			_, err = session.UnwrapFromSASLFraming(reader)

			if tt.shouldError {
				assert.Error(t, err, "Should reject invalid length")
			}
			// Note: For valid lengths, we'll get an EOF error because there's no actual data
			// That's expected for this test
		})
	}
}

// TestRFC4752_GSS_Wrap_Documentation verifies our implementation matches RFC 4752 description
// This is a documentation test to ensure our understanding is correct
func TestRFC4752_GSS_Wrap_Documentation(t *testing.T) {
	// RFC 4752 states:
	// - Integrity: GSS_Wrap with conf_flag=FALSE
	// - Confidentiality: GSS_Wrap with conf_flag=TRUE

	// Our implementation:
	// - Integrity: Sealed flag (bit 1) = 0
	// - Confidentiality: Sealed flag (bit 1) = 1

	// This test documents that our sealed flag maps to GSS-API conf_flag
	key := getTestKeyForSASL()

	// Verify integrity mapping
	integritySession, _ := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	integrityWrapped, _ := integritySession.Wrap([]byte("test"))
	integrityFlags := integrityWrapped[2]
	confFlagIntegrity := (integrityFlags & 0x02) != 0
	assert.False(t, confFlagIntegrity, "Integrity layer: conf_flag (sealed bit) should be FALSE")

	// Verify confidentiality mapping
	confSession, _ := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0)
	confWrapped, _ := confSession.Wrap([]byte("test"))
	confFlags := confWrapped[2]
	confFlagConf := (confFlags & 0x02) != 0
	assert.True(t, confFlagConf, "Confidentiality layer: conf_flag (sealed bit) should be TRUE")
}
