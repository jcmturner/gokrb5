package pac

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v5/testdata"
)

func TestPAC_ClientClaimsInfo_Unmarshal(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.TestVectors["PAC_ClientClaimsInfo"])
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k ClientClaimsInfo
	err = k.Unmarshal(b)
	t.Logf("%+v\n", k)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	assert.Equal(t, "testuser1", k.Claims.ClaimsSet.ClaimsArrays[0].ClaimsEntries[0].TypeString.Value, "claims value not as expected")
}
