package gssapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// generateTestCert creates a self-signed certificate for testing.
func generateTestCert(t *testing.T, sigAlgo x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	var privKey interface{}
	var pubKey interface{}

	switch sigAlgo {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		var curve elliptic.Curve
		switch sigAlgo {
		case x509.ECDSAWithSHA384:
			curve = elliptic.P384()
		case x509.ECDSAWithSHA512:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}
		privKey = key
		pubKey = &key.PublicKey
	default:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}
		privKey = key
		pubKey = &key.PublicKey
	}

	template.SignatureAlgorithm = sigAlgo

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func TestMakeTLSChannelBindingData_SHA256(t *testing.T) {
	cert := generateTestCert(t, x509.SHA256WithRSA)

	data, err := MakeTLSChannelBindingData(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should start with prefix
	if !strings.HasPrefix(string(data), TLSServerEndPointPrefix) {
		t.Errorf("expected prefix %q", TLSServerEndPointPrefix)
	}

	// SHA-256 hash is 32 bytes, so total length = len(prefix) + 32
	expectedLen := len(TLSServerEndPointPrefix) + 32
	if len(data) != expectedLen {
		t.Errorf("expected %d bytes, got %d", expectedLen, len(data))
	}
}

func TestMakeTLSChannelBindingData_HashAlgorithms(t *testing.T) {
	tests := []struct {
		name        string
		sigAlgo     x509.SignatureAlgorithm
		expectedLen int // len(prefix) + hash_size
	}{
		{"SHA256WithRSA", x509.SHA256WithRSA, len(TLSServerEndPointPrefix) + 32},
		{"SHA384WithRSA", x509.SHA384WithRSA, len(TLSServerEndPointPrefix) + 48},
		{"SHA512WithRSA", x509.SHA512WithRSA, len(TLSServerEndPointPrefix) + 64},
		{"SHA1WithRSA (uses SHA256)", x509.SHA1WithRSA, len(TLSServerEndPointPrefix) + 32},
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256, len(TLSServerEndPointPrefix) + 32},
		{"ECDSAWithSHA384", x509.ECDSAWithSHA384, len(TLSServerEndPointPrefix) + 48},
		{"ECDSAWithSHA512", x509.ECDSAWithSHA512, len(TLSServerEndPointPrefix) + 64},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := generateTestCert(t, tc.sigAlgo)
			data, err := MakeTLSChannelBindingData(cert)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(data) != tc.expectedLen {
				t.Errorf("expected %d bytes, got %d", tc.expectedLen, len(data))
			}
		})
	}
}

func TestMakeTLSChannelBindingData_NilCert(t *testing.T) {
	_, err := MakeTLSChannelBindingData(nil)
	if err == nil {
		t.Error("expected error for nil certificate")
	}
}

func TestMakeTLSChannelBindingData_Deterministic(t *testing.T) {
	cert := generateTestCert(t, x509.SHA256WithRSA)

	data1, err := MakeTLSChannelBindingData(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data2, err := MakeTLSChannelBindingData(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(data1) != string(data2) {
		t.Error("MakeTLSChannelBindingData should be deterministic")
	}
}

func TestNewTLSChannelBindingsFromCert(t *testing.T) {
	cert := generateTestCert(t, x509.SHA256WithRSA)

	cb, err := NewTLSChannelBindingsFromCert(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Address types should be unspecified
	if cb.InitiatorAddrType != AddressTypeUnspecified {
		t.Errorf("expected initiator addr type 0, got %d", cb.InitiatorAddrType)
	}
	if cb.AcceptorAddrType != AddressTypeUnspecified {
		t.Errorf("expected acceptor addr type 0, got %d", cb.AcceptorAddrType)
	}

	// Addresses should be empty
	if len(cb.InitiatorAddress) != 0 {
		t.Errorf("expected empty initiator address, got %d bytes", len(cb.InitiatorAddress))
	}
	if len(cb.AcceptorAddress) != 0 {
		t.Errorf("expected empty acceptor address, got %d bytes", len(cb.AcceptorAddress))
	}

	// ApplicationData should be set
	if len(cb.ApplicationData) == 0 {
		t.Error("ApplicationData should not be empty")
	}

	// ApplicationData should start with prefix
	if !strings.HasPrefix(string(cb.ApplicationData), TLSServerEndPointPrefix) {
		t.Errorf("ApplicationData should start with %q", TLSServerEndPointPrefix)
	}

	// MD5 hash should be valid and 16 bytes
	hash := cb.MD5Hash()
	if len(hash) != 16 {
		t.Errorf("expected 16 byte hash, got %d", len(hash))
	}
}

func TestNewTLSChannelBindingsFromCert_NilCert(t *testing.T) {
	_, err := NewTLSChannelBindingsFromCert(nil)
	if err == nil {
		t.Error("expected error for nil certificate")
	}
}

func TestNewTLSChannelBindingsFromState_NilState(t *testing.T) {
	_, err := NewTLSChannelBindingsFromState(nil)
	if err == nil {
		t.Error("expected error for nil state")
	}
}

func TestNewTLSChannelBindingsFromState_NoCerts(t *testing.T) {
	state := &tls.ConnectionState{}
	_, err := NewTLSChannelBindingsFromState(state)
	if err == nil {
		t.Error("expected error for empty certificates")
	}
}

func TestNewTLSChannelBindingsFromState_WithCert(t *testing.T) {
	cert := generateTestCert(t, x509.SHA256WithRSA)

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	cb, err := NewTLSChannelBindingsFromState(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the bindings are valid
	if len(cb.ApplicationData) == 0 {
		t.Error("ApplicationData should not be empty")
	}

	// Verify it produces the same result as NewTLSChannelBindingsFromCert
	cbFromCert, err := NewTLSChannelBindingsFromCert(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(cb.ApplicationData) != string(cbFromCert.ApplicationData) {
		t.Error("FromState and FromCert should produce identical ApplicationData")
	}
}

func TestNewTLSChannelBindingsFromState_MultipleCerts(t *testing.T) {
	// Create two certificates (simulating a certificate chain)
	leafCert := generateTestCert(t, x509.SHA256WithRSA)
	intermediateCert := generateTestCert(t, x509.SHA256WithRSA)

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leafCert, intermediateCert},
	}

	cb, err := NewTLSChannelBindingsFromState(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should use the leaf certificate (first in the chain)
	cbFromLeaf, err := NewTLSChannelBindingsFromCert(leafCert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(cb.ApplicationData) != string(cbFromLeaf.ApplicationData) {
		t.Error("should use leaf certificate for channel binding")
	}
}

func TestChannelBindings_Integration(t *testing.T) {
	// Test the full flow: cert -> channel bindings -> MD5 hash
	cert := generateTestCert(t, x509.SHA256WithRSA)

	cb, err := NewTLSChannelBindingsFromCert(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Marshal and verify
	marshaled := cb.Marshal()
	if len(marshaled) == 0 {
		t.Error("marshaled bindings should not be empty")
	}

	// Hash and verify
	hash := cb.MD5Hash()
	if len(hash) != 16 {
		t.Errorf("expected 16 byte hash, got %d", len(hash))
	}

	// Verify determinism of the full flow
	cb2, _ := NewTLSChannelBindingsFromCert(cert)
	if cb.MD5Hash() != cb2.MD5Hash() {
		t.Error("full flow should be deterministic")
	}
}
