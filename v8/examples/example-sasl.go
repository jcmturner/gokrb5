//go:build examples
// +build examples

package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
)

// This example demonstrates two scenarios for using SASL security layers with gokrb5:
// 1. Simple generic usage with basic Wrap/Unwrap and SASL framing
// 2. LDAP-style usage with security layer negotiation and SecureConn wrapper
//
// === GSS-API WrapToken Structure (RFC 4121) ===
// Byte 0-1:   Token ID (0x05 0x04)
// Byte 2:     Flags (acceptor, sealed, subkey)
// Byte 3:     Filler (0xFF)
// Byte 4-5:   EC (Extra Count) - meaning depends on sealed flag:
//             - Integrity tokens: EC = checksum size
//             - Confidentiality tokens: EC = filler size (usually 0)
// Byte 6-7:   RRC (Right Rotation Count)
//             - Windows AD commonly uses RRC for optimization
//             - Rotation: last RRC bytes moved to front after header
//             - Example: RRC=28 moves last 28 bytes to front
// Byte 8-15:  Sequence number (64-bit, prevents replay attacks)
// Byte 16+:   Payload (encrypted for confidentiality, plaintext for integrity)
// Byte N+:    Checksum (HMAC, only for integrity tokens)
//
// === SASL Framing (RFC 4422) ===
// Byte 0-3:   Length (big-endian, 32-bit, network byte order)
// Byte 4+:    Complete GSS-API WrapToken
//
// === Key Usage Values (RFC 4121) ===
// GSSAPI_ACCEPTOR_SEAL (22):  Server → Client messages
// GSSAPI_INITIATOR_SEAL (24): Client → Server messages
//
// === Security Features ===
// - Integrity: HMAC checksums (AES128/256-HMAC-SHA1-96)
// - Confidentiality: AES encryption with embedded integrity
// - Replay protection: Sequence number validation
// - Thread-safe: Mutex-protected sequence management
// - Windows AD compatible: RRC support tested with AD (Layer 2: RRC=12, Layer 4: RRC=28)
// - Production tested: LDAP operations on port 389 (no TLS) against Windows AD
// - Full RFC compliance: RFC 4121, RFC 4752, RFC 4422
//
// === Active Directory and TLS ===
// WARNING: Microsoft Active Directory (per MS-ADTS) prohibits using SASL security
// layers (integrity/confidentiality) over TLS connections. AD will reject such
// connections. This example demonstrates non-TLS usage, which is required for AD.
//
// If you use NewSecureConn() with a TLS connection and integrity/confidentiality
// layer, a warning will be logged to stderr by default. For non-AD LDAP servers
// that accept this per RFC 4513, suppress with GOKRB5_SASL_TLS_NO_WARN=1.

func main() {
	l := log.New(os.Stderr, "GOKRB5 SASL Example: ", log.Ldate|log.Ltime|log.Lshortfile)
	l.Println("=== SASL Security Layer Examples ===")

	// Scenario 1: Simple Generic Usage
	l.Println("--- Scenario 1: Simple Generic Usage ---")
	simpleGenericExample(l)

	l.Println("--- Scenario 2: LDAP-Style Usage ---")
	ldapStyleExample(l)
}

// simpleGenericExample demonstrates basic Wrap/Unwrap and SASL framing
func simpleGenericExample(l *log.Logger) {
	// Setup: Create a Kerberos client and get a session key
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_USER_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	cl := client.NewWithKeytab("testuser1", "USER.GOKRB5", kt, c, client.DisablePAFXFAST(true), client.Logger(l))
	err := cl.Login()
	if err != nil {
		l.Fatalf("Login failed: %v", err)
	}

	// Get a service ticket to obtain the session key
	tkt, sessionKey, err := cl.GetServiceTicket("HTTP/host.test.gokrb5")
	if err != nil {
		l.Fatalf("Failed to get service ticket: %v", err)
	}
	_ = tkt // Service ticket would be used in AP_REQ

	l.Println("✓ Obtained session key from Kerberos")

	// Create a SecurityLayerSession with Integrity layer (Layer 2)
	session, err := gssapi.NewSecurityLayerSession(
		sessionKey,
		gssapi.SecurityLayerIntegrity, // HMAC checksums
		true,                          // isInitiator: true for client, false for server
		65536,                         // maxMessageSize: 64KB limit
	)
	if err != nil {
		l.Fatalf("Failed to create security layer session: %v", err)
	}
	l.Println("✓ Created SecurityLayerSession with Integrity layer")

	// Basic Wrap/Unwrap
	message := []byte("Hello, secure world!")
	l.Printf("Original message: %s", message)

	// Wrap creates a GSS-API WrapToken (see file header for structure details)
	wrapped, err := session.Wrap(message)
	if err != nil {
		l.Fatalf("Failed to wrap message: %v", err)
	}

	l.Printf("Wrapped token: %d bytes (header=16, payload=%d, checksum=%d)",
		len(wrapped), len(message), len(wrapped)-16-len(message))

	// Unwrap verifies token ID, handles RRC rotation, verifies checksum, checks sequence
	receivedData := wrapped // Simulate network transmission
	unwrapped, err := session.Unwrap(receivedData)
	if err != nil {
		l.Fatalf("Failed to unwrap message: %v", err)
	}

	l.Printf("Unwrapped message: %s", unwrapped)
	l.Println("✓ Message integrity verified")

	// SASL Framing - used by protocols like LDAP, IMAP, SMTP
	// Adds 4-byte length prefix before GSS-API token
	l.Println("Testing SASL framing...")

	framedMessage, err := session.WrapWithSASLFraming(message)
	if err != nil {
		l.Fatalf("Failed to wrap with SASL framing: %v", err)
	}

	l.Printf("Framed message: %d bytes (prefix=4, token=%d)",
		len(framedMessage), len(framedMessage)-4)

	receivedFramed := framedMessage // Simulate network transmission
	unframedMessage, err := session.UnwrapFromSASLFraming(receivedFramed)
	if err != nil {
		l.Fatalf("Failed to unwrap from SASL framing: %v", err)
	}

	l.Printf("Unframed message: %s", unframedMessage)
	l.Println("✓ SASL framing handled correctly")

	// Note: For confidentiality (encryption), use SecurityLayerConfidentiality (Layer 4)
}

// ldapStyleExample demonstrates LDAP-style integration with SecureConn
// Real LDAP scenario:
// 1. TCP connection to LDAP server (port 389)
// 2. LDAP Bind with SASL/GSSAPI mechanism
// 3. Security layer negotiation (server offers layers, client chooses)
// 4. Wrap connection with SecureConn
// 5. All LDAP operations transparently protected
func ldapStyleExample(l *log.Logger) {
	// Setup: Authenticate with Kerberos
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_USER_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	cl := client.NewWithKeytab("testuser1", "USER.GOKRB5", kt, c, client.DisablePAFXFAST(true), client.Logger(l))
	err := cl.Login()
	if err != nil {
		l.Fatalf("Login failed: %v", err)
	}

	_, sessionKey, err := cl.GetServiceTicket("ldap/dc.example.com")
	if err != nil {
		l.Fatalf("Failed to get service ticket: %v", err)
	}

	l.Println("✓ GSSAPI authentication completed")

	// Simulate LDAP security layer negotiation
	// Real LDAP: server sends supported layers, client responds with chosen layer
	negotiatedLayer := gssapi.SecurityLayerIntegrity
	maxMessageSize := 65536

	l.Printf("✓ Negotiated security layer: %d (Integrity)", negotiatedLayer)
	l.Printf("✓ Max message size: %d bytes", maxMessageSize)

	// Create security layer session
	session, err := gssapi.NewSecurityLayerSession(
		sessionKey,
		negotiatedLayer,
		true, // Client side
		maxMessageSize,
	)
	if err != nil {
		l.Fatalf("Failed to create security layer session: %v", err)
	}

	// Simulate network connection (real: conn, err := net.Dial("tcp", "dc.example.com:389"))
	// NOTE: For Active Directory, use non-TLS port (389), not LDAPS/TLS port (636)
	// AD prohibits SASL security layers over TLS per MS-ADTS specification
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Wrap connection with SecureConn for transparent SASL protection
	secureConn := gssapi.NewSecureConn(clientConn, session)
	l.Println("✓ Connection wrapped with SecureConn")

	// Server side setup (for this simulation)
	serverSession, _ := gssapi.NewSecurityLayerSession(
		sessionKey,
		negotiatedLayer,
		false, // Server side (isInitiator=false)
		maxMessageSize,
	)
	secureServer := gssapi.NewSecureConn(serverConn, serverSession)

	// Simulate LDAP search request
	// All Read/Write operations are now automatically wrapped/unwrapped
	searchRequest := []byte("LDAP Search Request: (objectClass=user)")
	l.Printf("Client writes: %s", searchRequest)

	// Write is automatically wrapped with SASL framing
	_, err = secureConn.Write(searchRequest)
	if err != nil {
		l.Fatalf("Failed to write: %v", err)
	}
	l.Println("✓ Message automatically wrapped and sent")

	// Server reads - automatically unwrapped
	serverBuf := make([]byte, 4096)
	n, err := secureServer.Read(serverBuf)
	if err != nil {
		l.Fatalf("Server failed to read: %v", err)
	}

	receivedRequest := serverBuf[:n]
	l.Printf("Server received: %s", receivedRequest)
	l.Println("✓ Message automatically unwrapped")

	// Server sends response
	searchResponse := []byte("LDAP Search Response: 42 entries found")
	l.Printf("Server writes: %s", searchResponse)

	_, err = secureServer.Write(searchResponse)
	if err != nil {
		l.Fatalf("Server failed to write: %v", err)
	}

	// Client receives response - automatically unwrapped
	clientBuf := make([]byte, 4096)
	n, err = secureConn.Read(clientBuf)
	if err != nil {
		l.Fatalf("Client failed to read: %v", err)
	}

	receivedResponse := clientBuf[:n]
	l.Printf("Client received: %s", receivedResponse)
	l.Println("✓ Response automatically unwrapped")
	l.Println("✓ Bidirectional communication successful")
}
