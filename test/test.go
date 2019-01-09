package test

import (
	"os"
	"testing"
)

const (
	IntegrationEnvVar = "INTEGRATION"
)

func Integration(t *testing.T) {
	if os.Getenv(IntegrationEnvVar) != "1" {
		t.Skip("Skipping integration test")
	}
}
