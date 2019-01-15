package test

import (
	"os"
	"testing"
)

const (
	IntegrationEnvVar    = "INTEGRATION"
	ADIntegrationEnvVar  = "TESTAD"
	DNSIntegrationEnvVar = "TESTDNS"
)

func Integration(t *testing.T) {
	if os.Getenv(IntegrationEnvVar) != "1" {
		t.Skip("Skipping integration test")
	}
}

func AD(t *testing.T) {
	if os.Getenv(ADIntegrationEnvVar) != "1" {
		t.Skip("Skipping AD integration test")
	}
}

func DNS(t *testing.T) {
	if os.Getenv(DNSIntegrationEnvVar) != "1" {
		t.Skip("Skipping DNS integration test")
	}
}
