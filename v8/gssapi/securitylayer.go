package gssapi

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/crypto/etype"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Enable debug logging by setting GOKRB5_DEBUG=1 environment variable
var debugEnabled = os.Getenv("GOKRB5_DEBUG") == "1"

func debugLog(format string, args ...interface{}) {
	if debugEnabled {
		fmt.Printf("[GSSAPI DEBUG] "+format+"\n", args...)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SecurityLayer represents the SASL security layer type as defined in RFC 4752.
type SecurityLayer uint8

const (
	// SecurityLayerNone indicates no security layer (authentication only).
	SecurityLayerNone SecurityLayer = 1
	// SecurityLayerIntegrity indicates integrity protection (checksums).
	SecurityLayerIntegrity SecurityLayer = 2
	// SecurityLayerConfidentiality indicates confidentiality and integrity (encryption + checksums).
	SecurityLayerConfidentiality SecurityLayer = 4
)

// SecurityLayerSession manages GSS-API message wrapping for SASL security layers.
// It maintains sequence numbers and session keys for wrapping and unwrapping messages
// according to RFC 4121 (Kerberos GSS-API v2) and RFC 4752 (GSSAPI SASL mechanism).
type SecurityLayerSession struct {
	key            types.EncryptionKey
	layer          SecurityLayer
	isInitiator    bool
	sendSeqNum     uint64
	recvSeqNum     uint64
	maxMessageSize int
	mu             sync.Mutex
	encType        etype.EType
}

// NewSecurityLayerSession creates a new security layer session for wrapping/unwrapping messages.
// The isInitiator parameter should be true for clients and false for servers.
// The maxMessageSize parameter limits the size of unwrapped messages (0 for unlimited).
func NewSecurityLayerSession(key types.EncryptionKey, layer SecurityLayer, isInitiator bool, maxMessageSize int) (*SecurityLayerSession, error) {
	if layer != SecurityLayerNone && layer != SecurityLayerIntegrity && layer != SecurityLayerConfidentiality {
		return nil, fmt.Errorf("invalid security layer: %d", layer)
	}

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to get encryption type: %w", err)
	}

	return &SecurityLayerSession{
		key:            key,
		layer:          layer,
		isInitiator:    isInitiator,
		sendSeqNum:     0,
		recvSeqNum:     0,
		maxMessageSize: maxMessageSize,
		encType:        encType,
	}, nil
}

// Wrap wraps a message according to the negotiated security layer.
// For SecurityLayerNone, it returns the message unchanged.
// For SecurityLayerIntegrity, it adds a checksum.
// For SecurityLayerConfidentiality, it encrypts and adds integrity protection.
// The returned bytes include the GSS-API WrapToken format (RFC 4121).
//
// Encryption Model (two layers):
// 1. GSS-API layer (RFC 4121): Creates (message | filler | embedded-header)
// 2. Kerberos crypto layer (RFC 3961): Adds (confounder | data | padding)
//
// Final encrypted structure: Encrypt(confounder | message | filler | embedded-header) | HMAC
//
// The filler bytes ensure no padding is added after the embedded header, satisfying
// RFC 4121 section 4.2.4: "there SHALL be no crypto-system residue present after decryption."
func (s *SecurityLayerSession) Wrap(message []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	debugLog("WRAP: Input message length=%d", len(message))
	debugLog("WRAP: Input message (first %d bytes hex)=%x", min(len(message), 100), message[:min(len(message), 100)])
	debugLog("WRAP: Layer=%d, IsInitiator=%v, SeqNum=%d", s.layer, s.isInitiator, s.sendSeqNum)

	if s.layer == SecurityLayerNone {
		debugLog("WRAP: Layer is None, returning message unchanged")
		return message, nil
	}

	// Determine flags based on initiator status and security layer
	var flags byte
	if !s.isInitiator {
		flags |= 0x01 // Set acceptor flag
	}
	if s.layer == SecurityLayerConfidentiality {
		flags |= 0x02 // Set sealed (encrypted) flag
	}

	// Create wrap token early with flags and sequence number
	// EC and Payload will be set after determining encryption/integrity details
	token := &WrapToken{
		Flags:     flags,
		EC:        0, // Set after determining payload
		RRC:       0,
		SndSeqNum: s.sendSeqNum,
	}

	if s.layer == SecurityLayerConfidentiality {
		debugLog("WRAP: Creating confidentiality token")
		// RFC 4121 section 4.2.4: Encrypt(plaintext | filler | embedded-header)
		// Build the embedded header with EC=0 and RRC=0
		headerForCrypto := token.GetEmbeddedHeader()

		// Calculate filler size to eliminate crypto-system residue per RFC 4121 section 4.2.4.
		// This prevents RFC 3961's EncryptMessage from adding zero-padding after the embedded header.
		fillerSize := s.calculateFillerSize(len(message))
		toEncrypt := make([]byte, len(message)+fillerSize+16)
		copy(toEncrypt, message)
		// Filler bytes (if any) are already zero-initialized in the slice
		// They go between the message and the embedded header
		copy(toEncrypt[len(message)+fillerSize:], headerForCrypto)

		debugLog("WRAP: Encrypting %d bytes (message=%d + filler=%d + header=16)",
			len(toEncrypt), len(message), fillerSize)

		keyUsage := s.getKeyUsage(true)
		_, encryptedPayload, err := s.encType.EncryptMessage(s.key.KeyValue, toEncrypt, keyUsage)
		if err != nil {
			debugLog("WRAP: Encryption FAILED: %v", err)
			return nil, fmt.Errorf("failed to encrypt payload: %w", err)
		}
		token.Payload = encryptedPayload
		token.EC = uint16(fillerSize) // EC = filler size for confidentiality tokens
		debugLog("WRAP: Encrypted payload length=%d, EC=%d (filler size)", len(token.Payload), token.EC)
	} else {
		debugLog("WRAP: Creating integrity token")
		// For integrity-only, payload is plaintext
		token.Payload = message
		token.EC = uint16(s.encType.GetHMACBitLength() / 8) // EC = checksum size for integrity tokens
		debugLog("WRAP: Using plaintext payload, EC=%d (checksum size)", token.EC)
	}

	debugLog("WRAP: Token created - Flags=%#02x, EC=%d, RRC=%d, SeqNum=%d, PayloadLen=%d",
		token.Flags, token.EC, token.RRC, token.SndSeqNum, len(token.Payload))

	// Compute outer checksum only for integrity tokens
	// For confidentiality tokens, encryption provides integrity (no outer checksum)
	if s.layer != SecurityLayerConfidentiality {
		keyUsage := s.getKeyUsage(true)
		debugLog("WRAP: Computing outer checksum with key usage=%d", keyUsage)
		if err := token.SetCheckSum(s.key, keyUsage); err != nil {
			debugLog("WRAP: Checksum computation FAILED: %v", err)
			return nil, fmt.Errorf("failed to compute checksum: %w", err)
		}
		debugLog("WRAP: Checksum computed, length=%d", len(token.CheckSum))
	} else {
		debugLog("WRAP: Confidentiality token, no outer checksum needed")
		token.CheckSum = []byte{} // No outer checksum for confidentiality
	}

	// Increment sequence number for next message
	s.sendSeqNum++

	// Marshal token to bytes
	wrappedBytes, err := token.Marshal()
	if err != nil {
		debugLog("WRAP: Marshal FAILED: %v", err)
		return nil, fmt.Errorf("failed to marshal wrap token: %w", err)
	}

	debugLog("WRAP: Marshaled token length=%d", len(wrappedBytes))
	debugLog("WRAP: Marshaled token (first %d bytes hex)=%x", min(len(wrappedBytes), 100), wrappedBytes[:min(len(wrappedBytes), 100)])
	debugLog("WRAP: SUCCESS")

	return wrappedBytes, nil
}

// Unwrap unwraps a GSS-API wrapped message.
// For SecurityLayerNone, it returns the message unchanged.
// For SecurityLayerIntegrity and SecurityLayerConfidentiality, it verifies integrity
// and decrypts if necessary.
//
// Decryption process (two layers):
// 1. Kerberos crypto layer (RFC 3961): DecryptMessage removes confounder
//    Returns: message | filler | embedded-header (with no padding due to filler)
// 2. GSS-API layer (RFC 4121): Strips EC (filler size) + 16 (header) bytes
//    Returns: clean message
//
// The EC field in confidentiality tokens indicates the filler size, allowing us to
// extract the original message without any crypto-system residue.
func (s *SecurityLayerSession) Unwrap(wrappedMessage []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	debugLog("UNWRAP: Input wrapped message length=%d", len(wrappedMessage))
	debugLog("UNWRAP: Input wrapped message (first %d bytes hex)=%x", min(len(wrappedMessage), 100), wrappedMessage[:min(len(wrappedMessage), 100)])
	debugLog("UNWRAP: Layer=%d, IsInitiator=%v, ExpectedSeqNum>=%d", s.layer, s.isInitiator, s.recvSeqNum)

	if s.layer == SecurityLayerNone {
		debugLog("UNWRAP: Layer is None, returning message unchanged")
		return wrappedMessage, nil
	}

	// Parse the wrap token
	var token WrapToken
	expectFromAcceptor := s.isInitiator // If we're initiator, expect from acceptor
	debugLog("UNWRAP: Parsing WrapToken, expectFromAcceptor=%v", expectFromAcceptor)
	if err := token.Unmarshal(wrappedMessage, expectFromAcceptor); err != nil {
		debugLog("UNWRAP: Unmarshal FAILED: %v", err)
		return nil, fmt.Errorf("failed to unmarshal wrap token: %w", err)
	}

	debugLog("UNWRAP: Token parsed - Flags=%#02x, EC=%d, RRC=%d, SeqNum=%d, PayloadLen=%d",
		token.Flags, token.EC, token.RRC, token.SndSeqNum, len(token.Payload))
	debugLog("UNWRAP: Sealed flag set=%v", (token.Flags&0x02) != 0)

	// Handle RRC (Right Rotation Count) per RFC 4121 section 4.2.6.2
	// When RRC != 0, the encrypted/wrapped data is rotated right by RRC bytes
	// We need to un-rotate (rotate left) to restore original order
	if token.RRC != 0 {
		debugLog("UNWRAP: RRC=%d, performing un-rotation", token.RRC)
		rrc := int(token.RRC)

		// Reconstruct the message with proper rotation
		// The wrappedMessage is: [Header 16 bytes][Rotated Data]
		// We need to un-rotate everything after the header
		if len(wrappedMessage) > 16 {
			header := wrappedMessage[:16]
			rotatedData := wrappedMessage[16:]

			if rrc > 0 && rrc < len(rotatedData) {
				// Un-rotate: left rotation by RRC bytes
				// Move the first RRC bytes to the end
				unrotated := make([]byte, len(header)+len(rotatedData))
				copy(unrotated[:16], header)
				copy(unrotated[16:], rotatedData[rrc:])                      // Rest goes first
				copy(unrotated[16+len(rotatedData)-rrc:], rotatedData[:rrc]) // First RRC bytes go last

				debugLog("UNWRAP: Un-rotated data length=%d", len(rotatedData))

				// Replace the wrapped message with the un-rotated version
				wrappedMessage = unrotated

				// Re-parse the un-rotated token
				token = WrapToken{}
				if err := token.Unmarshal(unrotated, expectFromAcceptor); err != nil {
					debugLog("UNWRAP: Re-parse after un-rotation FAILED: %v", err)
					return nil, fmt.Errorf("failed to unmarshal un-rotated wrap token: %w", err)
				}
				debugLog("UNWRAP: After un-rotation - EC=%d, PayloadLen=%d, ChecksumLen=%d",
					token.EC, len(token.Payload), len(token.CheckSum))
			} else {
				debugLog("UNWRAP: WARNING: Invalid RRC value %d for data length %d", rrc, len(rotatedData))
			}
		}
	}

	// Verify sequence number (basic check - could be enhanced with replay detection)
	if token.SndSeqNum < s.recvSeqNum {
		debugLog("UNWRAP: Sequence number check FAILED: got %d, expected >= %d", token.SndSeqNum, s.recvSeqNum)
		return nil, fmt.Errorf("sequence number out of order: got %d, expected >= %d", token.SndSeqNum, s.recvSeqNum)
	}
	s.recvSeqNum = token.SndSeqNum + 1
	debugLog("UNWRAP: Sequence number OK, updated recvSeqNum to %d", s.recvSeqNum)

	// RFC 4121: For confidentiality tokens, the encryption operation provides integrity protection
	// There is NO separate checksum (EC=0 is correct for sealed tokens)
	// For integrity-only tokens, we need to verify the outer checksum
	isConfidentialityToken := (token.Flags&0x02) != 0 && token.EC == 0
	if isConfidentialityToken {
		debugLog("UNWRAP: Confidentiality token (sealed + EC=0), skipping outer checksum verification")
		debugLog("UNWRAP: Integrity will be verified during decryption")
	} else if token.EC > 0 {
		// Verify outer checksum for integrity-only tokens
		keyUsage := s.getKeyUsage(false)
		debugLog("UNWRAP: Integrity-only token, verifying outer checksum with key usage=%d", keyUsage)
		valid, err := token.Verify(s.key, keyUsage)
		if err != nil {
			debugLog("UNWRAP: Checksum verification ERROR: %v", err)
			return nil, fmt.Errorf("failed to verify checksum: %w", err)
		}
		if !valid {
			debugLog("UNWRAP: Checksum verification FAILED")
			return nil, errors.New("checksum verification failed")
		}
		debugLog("UNWRAP: Checksum verification SUCCESS")
	}

	// Extract payload - decrypt if sealed
	payload := token.Payload
	if token.Flags&0x02 != 0 { // Sealed flag is bit 1
		debugLog("UNWRAP: Sealed flag set, decrypting payload")
		keyUsage := s.getKeyUsage(false)
		debugLog("UNWRAP: Key usage for decryption=%d", keyUsage)
		decryptedPayload, err := s.encType.DecryptMessage(s.key.KeyValue, token.Payload, keyUsage)
		if err != nil {
			debugLog("UNWRAP: Decryption FAILED: %v", err)
			return nil, fmt.Errorf("failed to decrypt payload: %w", err)
		}
		debugLog("UNWRAP: Decrypted payload length=%d", len(decryptedPayload))

		// RFC 4121: Decrypted data is: plaintext | filler | embedded-header
		// EC field contains the filler size, embedded header is always 16 bytes
		// We need to strip the last (EC + 16) bytes to get the actual plaintext
		stripBytes := int(token.EC) + 16
		if len(decryptedPayload) < stripBytes {
			debugLog("UNWRAP: Decrypted payload too short: got %d bytes, need at least %d", len(decryptedPayload), stripBytes)
			return nil, fmt.Errorf("decrypted payload too short: %d bytes, expected at least %d", len(decryptedPayload), stripBytes)
		}
		payload = decryptedPayload[:len(decryptedPayload)-stripBytes]
		debugLog("UNWRAP: Stripped %d bytes (EC=%d filler + 16 byte embedded header), final payload length=%d",
			stripBytes, token.EC, len(payload))
	} else {
		debugLog("UNWRAP: No decryption needed (integrity layer)")
	}

	// Check message size if limit is set
	if s.maxMessageSize > 0 && len(payload) > s.maxMessageSize {
		debugLog("UNWRAP: Message size check FAILED: %d exceeds maximum %d", len(payload), s.maxMessageSize)
		return nil, fmt.Errorf("message size %d exceeds maximum %d", len(payload), s.maxMessageSize)
	}

	debugLog("UNWRAP: Extracted payload length=%d", len(payload))
	debugLog("UNWRAP: Extracted payload (first %d bytes hex)=%x", min(len(payload), 100), payload[:min(len(payload), 100)])
	debugLog("UNWRAP: SUCCESS")

	return payload, nil
}

// getKeyUsage returns the appropriate key usage constant based on direction.
func (s *SecurityLayerSession) getKeyUsage(sending bool) uint32 {
	if sending {
		if s.isInitiator {
			return keyusage.GSSAPI_INITIATOR_SEAL
		}
		return keyusage.GSSAPI_ACCEPTOR_SEAL
	}
	// Receiving: opposite of sending
	if s.isInitiator {
		return keyusage.GSSAPI_ACCEPTOR_SEAL
	}
	return keyusage.GSSAPI_INITIATOR_SEAL
}

// calculateFillerSize computes the number of filler bytes needed per RFC 4121 section 4.2.4
// to eliminate crypto-system residue after decryption.
//
// RFC 4121 states: "The values and size of the filler octets are chosen by implementations,
// such that there SHALL be no crypto-system residue present after the decryption."
//
// The encryption happens in two layers:
// 1. GSS-API (RFC 4121): Encrypts (message | filler | embedded-header)
// 2. Kerberos Crypto (RFC 3961): Adds confounder and may add zero-padding
//
// RFC 3961's EncryptMessage adds:
//   - Confounder at the beginning (typically 8 or 16 bytes)
//   - Zero-padding at the end to align to cipher block size
//
// The zero-padding added by RFC 3961 is NOT removed during decryption, so it becomes
// "crypto-system residue" that RFC 4121 requires us to eliminate. We do this by adding
// filler bytes BEFORE the embedded header so that the total length is already aligned,
// preventing RFC 3961 from adding any padding after the embedded header.
//
// Returns 0 for encryption types that don't need filler (AES-CTS, RC4).
func (s *SecurityLayerSession) calculateFillerSize(messageLen int) int {
	// Get the cipher block size in bytes
	blockSize := s.encType.GetCypherBlockBitLength() / 8

	// For stream ciphers or block size of 1, no filler needed
	if blockSize <= 1 {
		return 0
	}

	// For CTS (Ciphertext Stealing) modes, indicated by GetMessageBlockByteSize() == 1,
	// no filler is needed as CTS handles arbitrary lengths without padding
	if s.encType.GetMessageBlockByteSize() == 1 {
		return 0
	}

	// Calculate the total length that will be encrypted by RFC 3961:
	// confounder + message + filler + embedded-header (16 bytes)
	confounderSize := s.encType.GetConfounderByteSize()
	embeddedHeaderSize := 16

	// Current total without filler
	totalWithoutFiller := confounderSize + messageLen + embeddedHeaderSize

	// If already aligned to block size, no filler needed
	if totalWithoutFiller%blockSize == 0 {
		return 0
	}

	// Calculate filler to align to block size
	fillerSize := blockSize - (totalWithoutFiller % blockSize)

	debugLog("FILLER: blockSize=%d, confounderSize=%d, messageLen=%d, totalWithoutFiller=%d, fillerSize=%d",
		blockSize, confounderSize, messageLen, totalWithoutFiller, fillerSize)

	return fillerSize
}

// WrapWithSASLFraming wraps a message and prepends the 4-byte SASL length header.
// This is the format required by SASL protocols like LDAP with security layers.
// Format: [4-byte length (big-endian)][wrapped GSS-API token]
func (s *SecurityLayerSession) WrapWithSASLFraming(message []byte) ([]byte, error) {
	debugLog("SASL_WRAP: Input message length=%d", len(message))

	wrappedToken, err := s.Wrap(message)
	if err != nil {
		debugLog("SASL_WRAP: Wrap FAILED: %v", err)
		return nil, err
	}

	debugLog("SASL_WRAP: Wrapped token length=%d", len(wrappedToken))

	// Prepend 4-byte length header
	frameLength := uint32(len(wrappedToken))
	framedMessage := make([]byte, 4+len(wrappedToken))
	binary.BigEndian.PutUint32(framedMessage[0:4], frameLength)
	copy(framedMessage[4:], wrappedToken)

	debugLog("SASL_WRAP: SASL frame length=%d (0x%08x)", frameLength, frameLength)
	debugLog("SASL_WRAP: Final framed message length=%d (4-byte header + %d-byte token)", len(framedMessage), len(wrappedToken))
	debugLog("SASL_WRAP: Frame header (hex)=%x", framedMessage[0:4])
	debugLog("SASL_WRAP: SUCCESS")

	return framedMessage, nil
}

// UnwrapFromSASLFraming reads a SASL-framed message and unwraps it.
// This reads the 4-byte length header, then reads that many bytes and unwraps them.
// The reader parameter should be positioned at the start of a SASL-framed message.
func (s *SecurityLayerSession) UnwrapFromSASLFraming(reader io.Reader) ([]byte, error) {
	debugLog("SASL_UNWRAP: Reading SASL frame header (4 bytes)")

	// Read 4-byte length header
	var lengthBytes [4]byte
	if _, err := io.ReadFull(reader, lengthBytes[:]); err != nil {
		debugLog("SASL_UNWRAP: Failed to read frame length: %v", err)
		return nil, fmt.Errorf("failed to read SASL frame length: %w", err)
	}

	messageLength := binary.BigEndian.Uint32(lengthBytes[:])
	debugLog("SASL_UNWRAP: SASL frame length=%d (0x%08x)", messageLength, messageLength)
	debugLog("SASL_UNWRAP: Frame header (hex)=%x", lengthBytes[:])

	// Sanity check on message length
	if messageLength == 0 {
		debugLog("SASL_UNWRAP: Invalid frame length: 0")
		return nil, errors.New("invalid SASL frame length: 0")
	}
	if messageLength > 1<<24 { // 16MB limit
		debugLog("SASL_UNWRAP: Frame length too large: %d (max 16MB)", messageLength)
		return nil, fmt.Errorf("SASL frame length too large: %d", messageLength)
	}

	debugLog("SASL_UNWRAP: Reading wrapped message (%d bytes)", messageLength)

	// Read the wrapped message
	wrappedMessage := make([]byte, messageLength)
	if _, err := io.ReadFull(reader, wrappedMessage); err != nil {
		debugLog("SASL_UNWRAP: Failed to read wrapped message: %v", err)
		return nil, fmt.Errorf("failed to read wrapped message: %w", err)
	}

	debugLog("SASL_UNWRAP: Read %d bytes, unwrapping...", len(wrappedMessage))

	// Unwrap the message
	payload, err := s.Unwrap(wrappedMessage)
	if err != nil {
		debugLog("SASL_UNWRAP: Unwrap FAILED: %v", err)
		return nil, err
	}

	debugLog("SASL_UNWRAP: SUCCESS, payload length=%d", len(payload))
	return payload, nil
}

// SecureConn wraps a net.Conn to provide transparent SASL security layer protection.
// All data written is automatically wrapped, and all data read is automatically unwrapped.
// This implements the net.Conn interface.
type SecureConn struct {
	conn    net.Conn
	session *SecurityLayerSession
	readBuf []byte // Buffer for partially read unwrapped messages
}

// NewSecureConn creates a new SecureConn that wraps the provided connection.
// The session parameter configures the security layer behavior.
//
// WARNING: Microsoft Active Directory (per MS-ADTS) prohibits using SASL
// security layers (integrity/confidentiality) over TLS connections and will
// reject such connections. If a TLS connection is detected with an integrity
// or confidentiality layer, a warning will be logged to stderr by default.
// Set GOKRB5_SASL_TLS_NO_WARN=1 to suppress this warning if connecting to
// non-AD services that accept this configuration per RFC 4513.
func NewSecureConn(conn net.Conn, session *SecurityLayerSession) *SecureConn {
	// Check if the connection is TLS and warn about Active Directory incompatibility
	if _, isTLS := conn.(*tls.Conn); isTLS {
		if session.layer == SecurityLayerIntegrity || session.layer == SecurityLayerConfidentiality {
			// Warn by default unless explicitly suppressed
			if os.Getenv("GOKRB5_SASL_TLS_NO_WARN") != "1" {
				fmt.Fprintf(os.Stderr, "[GOKRB5 WARNING] Using SASL security layer over TLS connection. "+
					"Microsoft Active Directory (MS-ADTS) prohibits this combination and will reject the connection. "+
					"Other LDAP servers may accept this per RFC 4513. "+
					"Set GOKRB5_SASL_TLS_NO_WARN=1 to suppress this warning.\n")
			}
		}
	}

	return &SecureConn{
		conn:    conn,
		session: session,
		readBuf: make([]byte, 0),
	}
}

// Read reads data from the connection, automatically unwrapping SASL-framed messages.
// It implements the net.Conn Read method.
func (sc *SecureConn) Read(b []byte) (int, error) {
	// If we have buffered data from a previous unwrap, return that first
	if len(sc.readBuf) > 0 {
		n := copy(b, sc.readBuf)
		sc.readBuf = sc.readBuf[n:]
		return n, nil
	}

	// Read and unwrap a complete SASL-framed message
	unwrapped, err := sc.session.UnwrapFromSASLFraming(sc.conn)
	if err != nil {
		return 0, err
	}

	// Copy as much as we can to the caller's buffer
	n := copy(b, unwrapped)
	if n < len(unwrapped) {
		// Store remainder for next Read call
		sc.readBuf = append(sc.readBuf, unwrapped[n:]...)
	}

	return n, nil
}

// Write writes data to the connection, automatically wrapping with SASL framing.
// It implements the net.Conn Write method.
func (sc *SecureConn) Write(b []byte) (int, error) {
	wrapped, err := sc.session.WrapWithSASLFraming(b)
	if err != nil {
		return 0, err
	}

	// Write the complete wrapped message
	if _, err := sc.conn.Write(wrapped); err != nil {
		return 0, err
	}

	// Return the number of unwrapped bytes written (not the wrapped size)
	return len(b), nil
}

// Close closes the underlying connection.
func (sc *SecureConn) Close() error {
	return sc.conn.Close()
}

// LocalAddr returns the local network address.
func (sc *SecureConn) LocalAddr() net.Addr {
	return sc.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (sc *SecureConn) RemoteAddr() net.Addr {
	return sc.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines.
func (sc *SecureConn) SetDeadline(t time.Time) error {
	return sc.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (sc *SecureConn) SetReadDeadline(t time.Time) error {
	return sc.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (sc *SecureConn) SetWriteDeadline(t time.Time) error {
	return sc.conn.SetWriteDeadline(t)
}
