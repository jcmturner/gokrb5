package types

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v5/iana/adtype"
	"gopkg.in/jcmturner/gokrb5.v5/iana/nametype"
	"gopkg.in/jcmturner/gokrb5.v5/testdata"
)

func TestUnmarshalAuthorizationData(t *testing.T) {
	t.Parallel()
	var a AuthorizationData
	v := "encode_krb5_authorization_data"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, 2, len(a), "Number of authorization data entries not as expected")
	for i, entry := range a {
		assert.Equal(t, adtype.ADIfRelevant, entry.ADType, fmt.Sprintf("Authorization data type of entry %d not as expected", i+1))
		assert.Equal(t, []byte("foobar"), entry.ADData, fmt.Sprintf("Authorization data of entry %d not as expected", i+1))
	}
}

func TestUnmarshalAuthorizationData_kdcissued(t *testing.T) {
	t.Parallel()
	var a ADKDCIssued
	v := "encode_krb5_ad_kdcissued"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, int32(1), a.ADChecksum.CksumType, "Checksum type not as expected")
	assert.Equal(t, []byte("1234"), a.ADChecksum.Checksum, "Checksum not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.IRealm, "Issuing realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.Isname.NameType, "Issuing name type not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Isname.NameString, "Issuing name string entries not as expected")
	assert.Equal(t, 2, len(a.Elements), "Number of authorization data elements not as expected")
	for i, ele := range a.Elements {
		assert.Equal(t, adtype.ADIfRelevant, ele.ADType, fmt.Sprintf("Authorization data type of element %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_AUTHORIZATION_DATA_VALUE), ele.ADData, fmt.Sprintf("Authorization data of element %d not as expected", i+1))
	}
}
