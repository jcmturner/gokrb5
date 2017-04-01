package GSSAPI

import (
	"encoding/hex"
	"github.com/jcmturner/gokrb5/testdata"
	"github.com/jcmturner/gokrb5/types"
	"testing"
)

func TestKrb5Token_NewAPREQ(t *testing.T) {
	var tkt types.Ticket
	b, err := hex.DecodeString(testdata.TestVectors["encode_krb5_ticket"])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", "encode_krb5_ticket", err)
	}
	err = tkt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", "encode_krb5_ticket", err)
	}
	var a types.Authenticator
	//t.Logf("Starting unmarshal tests of %s", v)
	b, err = hex.DecodeString(testdata.TestVectors["encode_krb5_authenticator"])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", "encode_krb5_authenticator", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", "encode_krb5_authenticator", err)
	}
	var k types.EncryptionKey
	b, err = hex.DecodeString(testdata.TestVectors["encode_krb5_keyblock"])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", "encode_krb5_keyblock", err)
	}
	err = k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", "encode_krb5_keyblock", err)
	}
}
