package test

import (
	"os"
	"testing"
)

// Test enabling environment variable key values.
const (
	IntegrationEnvVar    = "INTEGRATION"
	ADIntegrationEnvVar  = "TESTAD"
	DNSIntegrationEnvVar = "TESTDNS"
)

// Integration skips the test unless the integration test environment variable is set.
func Integration(t *testing.T) {
	if os.Getenv(IntegrationEnvVar) != "1" {
		t.Skip("Skipping integration test")
	}
}

// AD skips the test unless the AD test environment variable is set.
func AD(t *testing.T) {
	if os.Getenv(ADIntegrationEnvVar) != "1" {
		t.Skip("Skipping AD integration test")
	}
}

// DNS skips the test unless the DNS test environment variable is set.
func DNS(t *testing.T) {
	if os.Getenv(DNSIntegrationEnvVar) != "1" {
		t.Skip("Skipping DNS integration test")
	}
}
