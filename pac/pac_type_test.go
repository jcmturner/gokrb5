package pac

import (
	"encoding/hex"
	"fmt"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/testdata"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPAC_Type_Validate(t *testing.T) {
	v := "PAC_AD_WIN2K_PAC"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	var pac PACType
	err = pac.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}

	b, _ = hex.DecodeString(testdata.SYSHTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	key, err := kt.GetEncryptionKey([]string{"sysHTTP"}, "TEST.GOKRB5", 2, 18)
	if err != nil {
		t.Fatalf("Error getting key: %v", err)
	}
	err = pac.ProcessPACInfoBuffers(key)
	if err != nil {
		t.Fatalf("Processing reference pac error: %v", err)
	}

	pac_invalid_server_sig := pac
	// Check the signature to force failure
	pac_invalid_server_sig.ServerChecksum.Signature[0] ^= 0xFF
	pac_invalid_nil_kerb_validation_info := pac
	pac_invalid_nil_kerb_validation_info.KerbValidationInfo = nil
	pac_invalid_nil_server_sig := pac
	pac_invalid_nil_server_sig.ServerChecksum = nil
	pac_invalid_nil_kdc_sig := pac
	pac_invalid_nil_kdc_sig.KDCChecksum = nil
	pac_invalid_client_info := pac
	pac_invalid_client_info.ClientInfo = nil

	var pacs = []struct {
		pac PACType
	}{
		{pac_invalid_server_sig},
		{pac_invalid_nil_kerb_validation_info},
		{pac_invalid_nil_server_sig},
		{pac_invalid_nil_kdc_sig},
		{pac_invalid_client_info},
	}
	for i, s := range pacs {
		v, _ := s.pac.validate(key)
		assert.False(t, v, fmt.Sprintf("Validation should have failed for test %v", i))
	}

}
