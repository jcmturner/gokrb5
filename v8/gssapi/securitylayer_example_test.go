package gssapi_test

import (
	"fmt"
	"log"
	"net"

	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ExampleSecurityLayerSession_basic demonstrates basic wrapping and unwrapping of messages
func ExampleSecurityLayerSession_basic() {
	// Assume we have obtained a session key from Kerberos authentication
	sessionKey := types.EncryptionKey{
		KeyType:  17, // AES128-CTS-HMAC-SHA1-96
		KeyValue: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
	}

	// Create a security layer session with integrity protection
	session, err := gssapi.NewSecurityLayerSession(
		sessionKey,
		gssapi.SecurityLayerIntegrity,
		true, // isInitiator (client)
		0,    // maxMessageSize (0 = unlimited)
	)
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}

	// Wrap a message
	message := []byte("Hello, SASL Security Layer!")
	wrapped, err := session.Wrap(message)
	if err != nil {
		log.Fatalf("Failed to wrap message: %v", err)
	}

	fmt.Printf("Original message: %s\n", message)
	fmt.Printf("Wrapped message length: %d bytes (greater than original)\n", len(wrapped))

	// On the receiving side, create a corresponding session
	serverSession, err := gssapi.NewSecurityLayerSession(
		sessionKey,
		gssapi.SecurityLayerIntegrity,
		false, // isInitiator = false (server/acceptor)
		0,
	)
	if err != nil {
		log.Fatalf("Failed to create server session: %v", err)
	}

	// Unwrap the message
	unwrapped, err := serverSession.Unwrap(wrapped)
	if err != nil {
		log.Fatalf("Failed to unwrap message: %v", err)
	}

	fmt.Printf("Unwrapped message: %s\n", unwrapped)
	// Output:
	// Original message: Hello, SASL Security Layer!
	// Wrapped message length: 55 bytes (greater than original)
	// Unwrapped message: Hello, SASL Security Layer!
}

// ExampleSecurityLayerSession_saslFraming demonstrates SASL-framed messages
// This is the format used by protocols like LDAP with security layers
func ExampleSecurityLayerSession_saslFraming() {
	sessionKey := types.EncryptionKey{
		KeyType:  17,
		KeyValue: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
	}

	// Create client session
	clientSession, err := gssapi.NewSecurityLayerSession(
		sessionKey,
		gssapi.SecurityLayerIntegrity,
		true,
		0,
	)
	if err != nil {
		log.Fatalf("Failed to create client session: %v", err)
	}

	// Wrap message with SASL framing (4-byte length prefix)
	message := []byte("LDAP Search Request")
	framedMessage, err := clientSession.WrapWithSASLFraming(message)
	if err != nil {
		log.Fatalf("Failed to wrap with SASL framing: %v", err)
	}

	fmt.Printf("Message: %s\n", message)
	fmt.Printf("Framed message has 4-byte length header plus wrapped token\n")
	fmt.Printf("Total framed length: %d bytes\n", len(framedMessage))

	// Output:
	// Message: LDAP Search Request
	// Framed message has 4-byte length header plus wrapped token
	// Total framed length: 51 bytes
}

// ExampleSecureConn demonstrates transparent wrapping/unwrapping with a network connection
// This is the easiest way to integrate SASL security layers into existing code
func ExampleSecureConn() {
	sessionKey := types.EncryptionKey{
		KeyType:  17,
		KeyValue: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
	}

	// Assume we have a net.Conn from LDAP connection
	var rawConn net.Conn // This would be your actual LDAP connection

	// After successful GSSAPI authentication and security layer negotiation,
	// wrap the connection with SecureConn
	clientSession, err := gssapi.NewSecurityLayerSession(
		sessionKey,
		gssapi.SecurityLayerIntegrity,
		true,
		0,
	)
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}

	// Wrap the raw connection
	secureConn := gssapi.NewSecureConn(rawConn, clientSession)

	// Now you can use secureConn like any net.Conn
	// All writes are automatically wrapped, all reads are automatically unwrapped

	// Example write (this would be an LDAP message in real usage)
	message := []byte("LDAP operation")
	_, err = secureConn.Write(message)
	if err != nil {
		log.Fatalf("Failed to write: %v", err)
	}

	// Example read (this would read an LDAP response in real usage)
	buffer := make([]byte, 4096)
	_, err = secureConn.Read(buffer)
	if err != nil {
		log.Fatalf("Failed to read: %v", err)
	}

	// Close when done
	secureConn.Close()
}

// ExampleSecurityLayerSession_ldapIntegration demonstrates how to integrate with go-ldap
func ExampleSecurityLayerSession_ldapIntegration() {
	// This is a conceptual example of how to integrate with go-ldap/ldap
	// After implementing security layer negotiation in go-ldap's GSSAPI bind:

	/*
		// 1. Perform GSSAPI bind and negotiate security layer
		bindRequest := &ldap.GSSAPIBindRequest{
			SecurityLayerPreference: &ldap.SecurityLayerPreference{
				PreferIntegrity:        true,
				PreferConfidentiality:  false,
				MaxReceiveBuffer:       65536,
			},
		}

		// 2. After successful bind, extract the session key from the Kerberos context
		sessionKey := extractSessionKeyFromKerberosContext(...)

		// 3. Determine the negotiated security layer
		negotiatedLayer := gssapi.SecurityLayerIntegrity // or SecurityLayerConfidentiality

		// 4. Create a security layer session
		session, err := gssapi.NewSecurityLayerSession(
			sessionKey,
			negotiatedLayer,
			true, // client is initiator
			65536, // max message size
		)
		if err != nil {
			log.Fatalf("Failed to create security layer session: %v", err)
		}

		// 5. Wrap the LDAP connection
		secureConn := gssapi.NewSecureConn(ldapConn.Conn, session)

		// 6. Replace the LDAP connection's net.Conn with the SecureConn
		ldapConn.Conn = secureConn

		// 7. Now all subsequent LDAP operations will be transparently wrapped/unwrapped
		searchRequest := ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"dn"},
			nil,
		)

		sr, err := ldapConn.Search(searchRequest)
		// The search request is automatically wrapped, response is automatically unwrapped
	*/

	fmt.Println("See code comments for integration pattern")
	// Output: See code comments for integration pattern
}
