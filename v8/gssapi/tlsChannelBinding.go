package gssapi

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// TLSServerEndPointPrefix is the channel binding prefix per RFC 5929 Section 4.1.
const TLSServerEndPointPrefix = "tls-server-end-point:"

// MakeTLSChannelBindingData creates the ApplicationData field for
// tls-server-end-point channel binding (RFC 5929 Section 4.1).
//
// The binding data format is: "tls-server-end-point:" + hash(server_certificate)
//
// The hash algorithm is determined by the certificate's signature algorithm per RFC 5929:
//   - MD5 or SHA-1 based signatures: use SHA-256
//   - SHA-256 based signatures: use SHA-256
//   - SHA-384 based signatures: use SHA-384
//   - SHA-512 based signatures: use SHA-512
//
// This is the most common channel binding type for TLS and works with both TLS 1.2 and TLS 1.3.
func MakeTLSChannelBindingData(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate cannot be nil")
	}

	var hash []byte

	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		h := sha512.Sum384(cert.Raw)
		hash = h[:]
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		h := sha512.Sum512(cert.Raw)
		hash = h[:]
	default:
		// MD5, SHA-1, SHA-256, and unknown algorithms use SHA-256
		// This covers: MD2WithRSA, MD5WithRSA, SHA1WithRSA, DSAWithSHA1,
		// ECDSAWithSHA1, SHA256WithRSA, SHA256WithRSAPSS, ECDSAWithSHA256, etc.
		h := sha256.Sum256(cert.Raw)
		hash = h[:]
	}

	// Construct: prefix + hash
	result := make([]byte, len(TLSServerEndPointPrefix)+len(hash))
	copy(result, TLSServerEndPointPrefix)
	copy(result[len(TLSServerEndPointPrefix):], hash)

	return result, nil
}

// NewTLSChannelBindingsFromState creates ChannelBindings from a TLS connection state.
// This is the primary entry point for LDAP CBT support after StartTLS.
//
// For tls-server-end-point, only the ApplicationData field is populated.
// The initiator/acceptor address fields are left empty (this is standard practice
// for TLS channel bindings as the binding is to the TLS channel itself, not specific addresses).
//
// Usage example:
//
//	conn.StartTLS(tlsConfig)
//	cs, _ := conn.TLSConnectionState()
//	cb, err := gssapi.NewTLSChannelBindingsFromState(&cs)
func NewTLSChannelBindingsFromState(state *tls.ConnectionState) (*ChannelBindings, error) {
	if state == nil {
		return nil, fmt.Errorf("TLS connection state cannot be nil")
	}

	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates in TLS connection state")
	}

	// Use the leaf certificate (first in the chain)
	leafCert := state.PeerCertificates[0]

	appData, err := MakeTLSChannelBindingData(leafCert)
	if err != nil {
		return nil, fmt.Errorf("failed to create channel binding data: %w", err)
	}

	return &ChannelBindings{
		InitiatorAddrType: AddressTypeUnspecified,
		AcceptorAddrType:  AddressTypeUnspecified,
		ApplicationData:   appData,
	}, nil
}

// NewTLSChannelBindingsFromCert creates ChannelBindings directly from a certificate.
// This is useful when you have the certificate but not a full connection state,
// for example when testing or when the certificate is obtained through other means.
func NewTLSChannelBindingsFromCert(cert *x509.Certificate) (*ChannelBindings, error) {
	appData, err := MakeTLSChannelBindingData(cert)
	if err != nil {
		return nil, err
	}

	return &ChannelBindings{
		InitiatorAddrType: AddressTypeUnspecified,
		AcceptorAddrType:  AddressTypeUnspecified,
		ApplicationData:   appData,
	}, nil
}
