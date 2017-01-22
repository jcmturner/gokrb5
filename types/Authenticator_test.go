package types

import (
	"encoding/hex"
	"fmt"
	"github.com/jcmturner/gokrb5/testdata"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

const (
	tf     = "20060102150405"
	trealm = "ATHENA.MIT.EDU"
)

func unmarshal(t *testing.T, v string) Authenticator {
	var a Authenticator
	//t.Logf("Starting unmarshal tests of %s", v)
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	return a
}
func TestUnmarshalAuthenticator(t *testing.T) {
	a := unmarshal(t, "encode_krb5_authenticator")
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(tf, "19940610060317")

	assert.Equal(t, 5, a.AVNO, "Authenticator version number not as expected")
	assert.Equal(t, trealm, a.CRealm, "CRealm not as expected")
	assert.Equal(t, 1, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, 2, len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, "hftsai", a.CName.NameString[0], "CName first entry not as expected")
	assert.Equal(t, "extra", a.CName.NameString[1], "CName second entry not as expected")
	assert.Equal(t, 1, a.Cksum.CksumType, "Checksum type not as expected")
	assert.Equal(t, []byte("1234"), a.Cksum.Checksum, "Checsum not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, tt, a.CTime, "Client time not as expected")
	assert.Equal(t, 1, a.SubKey.KeyType, "Subkey type not as expected")
	assert.Equal(t, []byte("12345678"), a.SubKey.KeyValue, "Subkey value not as expected")
	assert.Equal(t, 2, len(a.AuthorizationData), "Number of Authorization data items not as expected")
	for i, entry := range a.AuthorizationData {
		assert.Equal(t, 1, entry.ADType, fmt.Sprintf("Authorization type of entry %d not as expected", i+1))
		assert.Equal(t, []byte("foobar"), entry.ADData, fmt.Sprintf("Authorization data of entry %d not as expected", i+1))
	}
}

func TestUnmarshalAuthenticator_optionalsempty(t *testing.T) {
	a := unmarshal(t, "encode_krb5_authenticator(optionalsempty)")
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(tf, "19940610060317")

	assert.Equal(t, 5, a.AVNO, "Authenticator version number not as expected")
	assert.Equal(t, trealm, a.CRealm, "CRealm not as expected")
	assert.Equal(t, 1, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, 2, len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, "hftsai", a.CName.NameString[0], "CName first entry not as expected")
	assert.Equal(t, "extra", a.CName.NameString[1], "CName second entry not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, tt, a.CTime, "Client time not as expected")
}

func TestUnmarshalAuthenticator_optionalsNULL(t *testing.T) {
	a := unmarshal(t, "encode_krb5_authenticator(optionalsNULL)")
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(tf, "19940610060317")

	assert.Equal(t, 5, a.AVNO, "Authenticator version number not as expected")
	assert.Equal(t, trealm, a.CRealm, "CRealm not as expected")
	assert.Equal(t, 1, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, 2, len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, "hftsai", a.CName.NameString[0], "CName first entry not as expected")
	assert.Equal(t, "extra", a.CName.NameString[1], "CName second entry not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, tt, a.CTime, "Client time not as expected")
}
