package config

import (
	"testing"
)

func TestConfig_GetKDCsUsesConfiguredKDC(t *testing.T) {
	t.Parallel()

	// This test is meant to cover the fix for
	// https://github.com/jcmturner/gokrb5/issues/332
	krb5ConfWithKDCAndDNSLookupKDC := `
[libdefaults]
 dns_lookup_kdc = true

[realms]
 TEST.GOKRB5 = {
  kdc = kdc2b.test.gokrb5:88
 }
`

	c, err := NewConfigFromString(krb5ConfWithKDCAndDNSLookupKDC)
	if err != nil {
		t.Fatalf("Error loading config: %v", err)
	}

	count, kdcs, err := c.GetKDCs("TEST.GOKRB5", false)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 but received %d", count)
	}
	if kdcs[1] != "kdc2b.test.gokrb5:88" {
		t.Fatalf("expected kdc2b.test.gokrb5:88 but received %s", kdcs[1])
	}
}
