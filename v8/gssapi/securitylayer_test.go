package gssapi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Test session key (from wrapToken_test.go)
const (
	testSessionKey     = "14f9bde6b50ec508201a97f74c4e5bd3"
	testSessionKeyType = 17 // AES128-CTS-HMAC-SHA1-96
)

func getTestSessionKey() types.EncryptionKey {
	key, _ := hex.DecodeString(testSessionKey)
	return types.EncryptionKey{
		KeyType:  testSessionKeyType,
		KeyValue: key,
	}
}

func TestNewSecurityLayerSession(t *testing.T) {
	key := getTestSessionKey()

	tests := []struct {
		name        string
		layer       SecurityLayer
		isInitiator bool
		maxMsgSize  int
		shouldError bool
	}{
		{"None layer", SecurityLayerNone, true, 0, false},
		{"Integrity layer", SecurityLayerIntegrity, true, 0, false},
		{"Confidentiality layer", SecurityLayerConfidentiality, true, 0, false},
		{"With max message size", SecurityLayerIntegrity, true, 1024, false},
		{"Invalid layer", SecurityLayer(99), true, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, err := NewSecurityLayerSession(key, tt.layer, tt.isInitiator, tt.maxMsgSize)
			if tt.shouldError {
				assert.Error(t, err)
				assert.Nil(t, session)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, session)
				assert.Equal(t, tt.layer, session.layer)
				assert.Equal(t, tt.isInitiator, session.isInitiator)
				assert.Equal(t, tt.maxMsgSize, session.maxMessageSize)
				assert.Equal(t, uint64(0), session.sendSeqNum)
				assert.Equal(t, uint64(0), session.recvSeqNum)
			}
		})
	}
}

func TestSecurityLayerSession_WrapUnwrap_None(t *testing.T) {
	key := getTestSessionKey()
	message := []byte("Hello, SASL!")

	// Create sessions for both sides
	clientSession, err := NewSecurityLayerSession(key, SecurityLayerNone, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerNone, false, 0)
	require.NoError(t, err)

	// Wrap from client
	wrapped, err := clientSession.Wrap(message)
	assert.NoError(t, err)
	assert.Equal(t, message, wrapped) // No wrapping for SecurityLayerNone

	// Unwrap on server
	unwrapped, err := serverSession.Unwrap(wrapped)
	assert.NoError(t, err)
	assert.Equal(t, message, unwrapped)
}

func TestSecurityLayerSession_WrapUnwrap_Integrity(t *testing.T) {
	key := getTestSessionKey()
	message := []byte("Hello, SASL with integrity!")

	// Create sessions for both sides
	clientSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
	require.NoError(t, err)

	// Wrap from client
	wrapped, err := clientSession.Wrap(message)
	assert.NoError(t, err)
	assert.NotEqual(t, message, wrapped) // Should be wrapped
	assert.Greater(t, len(wrapped), len(message)) // Wrapped should be larger

	// Verify it's a valid GSS-API token
	assert.Equal(t, byte(0x05), wrapped[0])
	assert.Equal(t, byte(0x04), wrapped[1])

	// Unwrap on server
	unwrapped, err := serverSession.Unwrap(wrapped)
	assert.NoError(t, err)
	assert.Equal(t, message, unwrapped)
}

func TestSecurityLayerSession_WrapUnwrap_Confidentiality(t *testing.T) {
	key := getTestSessionKey()
	message := []byte("Hello, SASL with confidentiality!")

	// Create sessions for both sides
	clientSession, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, false, 0)
	require.NoError(t, err)

	// Wrap from client
	wrapped, err := clientSession.Wrap(message)
	assert.NoError(t, err)
	assert.NotEqual(t, message, wrapped) // Should be wrapped
	assert.Greater(t, len(wrapped), len(message)) // Wrapped should be larger

	// Verify it's a valid GSS-API token
	assert.Equal(t, byte(0x05), wrapped[0])
	assert.Equal(t, byte(0x04), wrapped[1])

	// Verify sealed flag is set
	assert.Equal(t, byte(0x02), wrapped[2]&0x02, "sealed flag should be set")

	// Verify payload is encrypted (should not contain plaintext)
	assert.NotContains(t, string(wrapped), string(message), "plaintext should not be visible in wrapped message")

	// Unwrap on server
	unwrapped, err := serverSession.Unwrap(wrapped)
	assert.NoError(t, err)
	assert.Equal(t, message, unwrapped)
}

func TestSecurityLayerSession_Confidentiality_MultipleMessages(t *testing.T) {
	key := getTestSessionKey()

	clientSession, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, false, 0)
	require.NoError(t, err)

	messages := []string{
		"First encrypted message",
		"Second encrypted message",
		"Third encrypted message",
	}

	for i, msg := range messages {
		wrapped, err := clientSession.Wrap([]byte(msg))
		assert.NoError(t, err)

		// Verify sequence number increments
		var token WrapToken
		err = token.Unmarshal(wrapped, false)
		assert.NoError(t, err)
		assert.Equal(t, uint64(i), token.SndSeqNum)

		// Verify sealed flag is set
		assert.Equal(t, byte(0x02), token.Flags&0x02, "sealed flag should be set")

		unwrapped, err := serverSession.Unwrap(wrapped)
		assert.NoError(t, err)
		assert.Equal(t, msg, string(unwrapped))
	}
}

func TestSecurityLayerSession_WrapUnwrap_MultipleMessages(t *testing.T) {
	key := getTestSessionKey()

	clientSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
	require.NoError(t, err)

	messages := []string{
		"First message",
		"Second message",
		"Third message",
	}

	for i, msg := range messages {
		wrapped, err := clientSession.Wrap([]byte(msg))
		assert.NoError(t, err)

		// Verify sequence number increments
		var token WrapToken
		err = token.Unmarshal(wrapped, false)
		assert.NoError(t, err)
		assert.Equal(t, uint64(i), token.SndSeqNum)

		unwrapped, err := serverSession.Unwrap(wrapped)
		assert.NoError(t, err)
		assert.Equal(t, msg, string(unwrapped))
	}
}

func TestSecurityLayerSession_SequenceNumberValidation(t *testing.T) {
	key := getTestSessionKey()

	clientSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
	require.NoError(t, err)

	// Wrap two messages
	msg1 := []byte("Message 1")
	msg2 := []byte("Message 2")

	wrapped1, err := clientSession.Wrap(msg1)
	require.NoError(t, err)
	wrapped2, err := clientSession.Wrap(msg2)
	require.NoError(t, err)

	// Receive in order - should work
	_, err = serverSession.Unwrap(wrapped1)
	assert.NoError(t, err)
	_, err = serverSession.Unwrap(wrapped2)
	assert.NoError(t, err)

	// Try to replay message 1 - should fail
	_, err = serverSession.Unwrap(wrapped1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sequence number out of order")
}

func TestSecurityLayerSession_MaxMessageSize(t *testing.T) {
	key := getTestSessionKey()
	maxSize := 10

	clientSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, maxSize)
	require.NoError(t, err)

	// Message within limit
	smallMsg := []byte("Small")
	wrapped, err := clientSession.Wrap(smallMsg)
	require.NoError(t, err)
	unwrapped, err := serverSession.Unwrap(wrapped)
	assert.NoError(t, err)
	assert.Equal(t, smallMsg, unwrapped)

	// Message exceeding limit
	largeMsg := []byte("This is a very large message")
	wrapped, err = clientSession.Wrap(largeMsg)
	require.NoError(t, err)
	_, err = serverSession.Unwrap(wrapped)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestSecurityLayerSession_WrapWithSASLFraming(t *testing.T) {
	key := getTestSessionKey()
	message := []byte("Test message")

	session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	framed, err := session.WrapWithSASLFraming(message)
	assert.NoError(t, err)

	// Should have 4-byte length prefix
	assert.GreaterOrEqual(t, len(framed), 4)

	// Extract length
	length := binary.BigEndian.Uint32(framed[0:4])
	assert.Equal(t, uint32(len(framed)-4), length)

	// Verify token starts after length
	assert.Equal(t, byte(0x05), framed[4])
	assert.Equal(t, byte(0x04), framed[5])
}

func TestSecurityLayerSession_UnwrapFromSASLFraming(t *testing.T) {
	key := getTestSessionKey()
	message := []byte("Test message for SASL framing")

	clientSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
	require.NoError(t, err)

	// Wrap with framing
	framed, err := clientSession.WrapWithSASLFraming(message)
	require.NoError(t, err)

	// Create a reader from the framed bytes
	reader := bytes.NewReader(framed)

	// Unwrap from framing
	unwrapped, err := serverSession.UnwrapFromSASLFraming(reader)
	assert.NoError(t, err)
	assert.Equal(t, message, unwrapped)
}

func TestSecurityLayerSession_UnwrapFromSASLFraming_Errors(t *testing.T) {
	key := getTestSessionKey()

	session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	tests := []struct {
		name        string
		data        []byte
		expectError string
	}{
		{
			name:        "Empty data",
			data:        []byte{},
			expectError: "failed to read SASL frame length",
		},
		{
			name:        "Incomplete length header",
			data:        []byte{0x00, 0x00},
			expectError: "failed to read SASL frame length",
		},
		{
			name:        "Zero length",
			data:        []byte{0x00, 0x00, 0x00, 0x00},
			expectError: "invalid SASL frame length: 0",
		},
		{
			name:        "Length too large",
			data:        []byte{0x7F, 0xFF, 0xFF, 0xFF}, // 2GB
			expectError: "SASL frame length too large",
		},
		{
			name:        "Incomplete message",
			data:        []byte{0x00, 0x00, 0x00, 0x10, 0x05, 0x04}, // Says 16 bytes but only 2
			expectError: "failed to read wrapped message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader(tt.data)
			_, err := session.UnwrapFromSASLFraming(reader)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

// mockConn is a mock net.Conn implementation for testing
type mockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
}

func newMockConn() *mockConn {
	return &mockConn{
		readBuf:  new(bytes.Buffer),
		writeBuf: new(bytes.Buffer),
	}
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.closed {
		return 0, io.EOF
	}
	return m.readBuf.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	return m.writeBuf.Write(b)
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestSecureConn_Write(t *testing.T) {
	key := getTestSessionKey()
	message := []byte("Test message for SecureConn")

	session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	mockConn := newMockConn()
	secureConn := NewSecureConn(mockConn, session)

	// Write should wrap and frame the message
	n, err := secureConn.Write(message)
	assert.NoError(t, err)
	assert.Equal(t, len(message), n) // Should return original message length

	// Check that data was written to underlying connection
	written := mockConn.writeBuf.Bytes()
	assert.Greater(t, len(written), len(message)) // Should be wrapped

	// Verify SASL framing
	length := binary.BigEndian.Uint32(written[0:4])
	assert.Equal(t, uint32(len(written)-4), length)

	// Verify GSS-API token
	assert.Equal(t, byte(0x05), written[4])
	assert.Equal(t, byte(0x04), written[5])
}

func TestSecureConn_Read(t *testing.T) {
	key := getTestSessionKey()
	message := []byte("Test message for SecureConn read")

	// Create client and server sessions
	clientSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
	require.NoError(t, err)

	// Wrap message as client
	framedMessage, err := clientSession.WrapWithSASLFraming(message)
	require.NoError(t, err)

	// Set up mock connection with the framed message
	mockConn := newMockConn()
	mockConn.readBuf.Write(framedMessage)

	secureConn := NewSecureConn(mockConn, serverSession)

	// Read should unwrap the message
	buf := make([]byte, 1024)
	n, err := secureConn.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, len(message), n)
	assert.Equal(t, message, buf[:n])
}

func TestSecureConn_Read_PartialBuffer(t *testing.T) {
	key := getTestSessionKey()
	message := []byte("This is a longer test message for SecureConn")

	clientSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
	require.NoError(t, err)

	// Wrap message
	framedMessage, err := clientSession.WrapWithSASLFraming(message)
	require.NoError(t, err)

	// Set up mock connection
	mockConn := newMockConn()
	mockConn.readBuf.Write(framedMessage)

	secureConn := NewSecureConn(mockConn, serverSession)

	// Read with small buffer - should require multiple reads
	smallBuf := make([]byte, 10)
	var received []byte

	for len(received) < len(message) {
		n, err := secureConn.Read(smallBuf)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("Unexpected error: %v", err)
		}
		received = append(received, smallBuf[:n]...)
	}

	assert.Equal(t, message, received)
}

func TestSecureConn_RoundTrip(t *testing.T) {
	key := getTestSessionKey()

	// Create client and server sessions
	clientSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
	require.NoError(t, err)

	// Create mock connections (each side's write goes to other side's read)
	clientWriteConn := newMockConn()
	serverWriteConn := newMockConn()

	// Create a bidirectional setup
	clientConn := &mockConn{
		writeBuf: clientWriteConn.writeBuf,
		readBuf:  serverWriteConn.writeBuf,
	}
	serverConn := &mockConn{
		writeBuf: serverWriteConn.writeBuf,
		readBuf:  clientWriteConn.writeBuf,
	}

	secureClient := NewSecureConn(clientConn, clientSession)
	secureServer := NewSecureConn(serverConn, serverSession)

	// Client sends to server
	clientMsg := []byte("Hello from client")
	n, err := secureClient.Write(clientMsg)
	assert.NoError(t, err)
	assert.Equal(t, len(clientMsg), n)

	// Server receives from client
	buf := make([]byte, 1024)
	n, err = secureServer.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, clientMsg, buf[:n])

	// Server replies to client
	serverMsg := []byte("Hello from server")
	n, err = secureServer.Write(serverMsg)
	assert.NoError(t, err)
	assert.Equal(t, len(serverMsg), n)

	// Client receives from server
	n, err = secureClient.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, serverMsg, buf[:n])
}

func TestSecureConn_Close(t *testing.T) {
	key := getTestSessionKey()
	session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	mockConn := newMockConn()
	secureConn := NewSecureConn(mockConn, session)

	err = secureConn.Close()
	assert.NoError(t, err)
	assert.True(t, mockConn.closed)
}
