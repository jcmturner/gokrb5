package pac

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v5/mstypes"
	"gopkg.in/jcmturner/gokrb5.v5/testdata"
)

const (
	ClaimsEntryID    = "ad://ext/sAMAccountName:88d5d9085ea5c0c0"
	ClaimsEntryValue = "testuser1"
)

func TestPAC_ClientClaimsInfo_Unmarshal(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.TestVectors["PAC_ClientClaimsInfo"])
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k ClientClaimsInfo
	err = k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	assert.Equal(t, uint32(1), k.Claims.ClaimsSet.ClaimsArrayCount, "claims array count not as expected")
	assert.Equal(t, mstypes.ClaimsSourceTypeAD, k.Claims.ClaimsSet.ClaimsArrays[0].ClaimsSourceType, "claims source type not as expected")
	assert.Equal(t, uint32(1), k.Claims.ClaimsSet.ClaimsArrays[0].ClaimsCount, "claims count not as expected")
	assert.Equal(t, uint16(3), k.Claims.ClaimsSet.ClaimsArrays[0].ClaimsEntries[0].Type, "claims entry type not as expected")
	assert.Equal(t, uint32(1), k.Claims.ClaimsSet.ClaimsArrays[0].ClaimsEntries[0].TypeString.ValueCount, "claims value count not as expected")
	assert.Equal(t, ClaimsEntryID, k.Claims.ClaimsSet.ClaimsArrays[0].ClaimsEntries[0].ID, "claims entry ID not as expected")
	assert.Equal(t, []string{ClaimsEntryValue}, k.Claims.ClaimsSet.ClaimsArrays[0].ClaimsEntries[0].TypeString.Value, "claims value not as expected")
	assert.Equal(t, mstypes.CompressionFormatNone, k.Claims.CompressionFormat, "compression format not as expected")

}
