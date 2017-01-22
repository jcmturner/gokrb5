package types

import (
	"encoding/hex"
	"github.com/jcmturner/gokrb5/testdata"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUnmarshalTicket(t *testing.T) {
	var a Ticket
	v := "encode_krb5_ticket"
	//t.Logf("Starting unmarshal tests of %s", v)
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}

	assert.Equal(t, testdata.TEST_KVNO, a.TktVNO, "Ticket version number not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.SName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString), "SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "SName name strings not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Etype of Ticket EncPart not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.EncPart.KVNO, "KNVO of Ticket EncPart not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncPart.Cipher, "Cipher of Ticket EncPart not as expected")
}
