package messages

import (
	"encoding/hex"
	"github.com/jcmturner/gokrb5/testdata"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestUnmarshalASReqDecode(t *testing.T) {
	/*d := "encode_krb5_as_req"
	t.Logf("Starting unmarshal tests of %s", d)
	b, err := hex.DecodeString(testdata.TestVectors[d])
	if err != nil {
		t.Fatalf("AS REQ read error: %v\n", err)
	}
	m, err := UnmarshalASReq(b)
	if err != nil {
		t.Fatalf("AS REQ Unmarshal error of %s: %v\n", d, err)
	}
	assert.Equal(t, 2, len(m.PAData), "PAData does not have the expected number of entries")
	assert.Equal(t, 13, m.PAData[0].PADataType, "PADataType of first PAData entry is not as expected")
	assert.Equal(t, "pa-data", string(m.PAData[0].PADataValue), "PADataValue of first PAData entry is not as expected")
	assert.Equal(t, 13, m.PAData[1].PADataType, "PADataType of second PAData entry is not as expected")
	assert.Equal(t, "pa-data", string(m.PAData[1].PADataValue), "PADataValue of second PAData entry is not as expected")
	assert.Equal(t, 1, m.ReqBody.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, 2, len(m.ReqBody.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, "hftsai", m.ReqBody.CName.NameString[0], "CName first entry not as expected")
	assert.Equal(t, "extra", m.ReqBody.CName.NameString[1], "CName second entry not as expected")*/

	d := "encode_krb5_as_req(optionalsNULLexceptserver)"
	t.Logf("Starting unmarshal tests of %s", d)
	b, err := hex.DecodeString(testdata.TestVectors[d])
	if err != nil {
		t.Fatalf("AS REQ read error: %v\n", err)
	}
	m, err := UnmarshalASReq(b)
	if err != nil {
		t.Fatalf("AS REQ Unmarshal error of %s: %v\n", d, err)
	}
	assert.Equal(t, 5, m.PVNO, "PVNO not as expected")
	assert.Equal(t, 10, m.MsgType, "MsgType not as expected")
	assert.Equal(t, "fedcba90", hex.EncodeToString(m.ReqBody.KDCOptions.Bytes), "KDCOptions in request body not as expected")
	assert.Equal(t, "ATHENA.MIT.EDU", m.ReqBody.Realm, "Ticket Realm not as expected")
	assert.Equal(t, 1, m.ReqBody.SName.NameType, "SName NameType not as expected")
	assert.Equal(t, 2, len(m.ReqBody.SName.NameString), "SName does not have the expected number of NameStrings")
	assert.Equal(t, "hftsai", m.ReqBody.SName.NameString[0], "SName first entry not as expected")
	assert.Equal(t, "extra", m.ReqBody.SName.NameString[1], "SName second entry not as expected")
	assert.Equal(t, 19940610060317, m.ReqBody.Till.Unix(), "Till time is not as expected")
}

func TestUnmarshalASReq(t *testing.T) {
	d, _ := os.Getwd()
	asreqData, err := ioutil.ReadFile(d + "/../testdata/AS-REQ.raw")
	if err != nil {
		t.Fatalf("AS REP read error: %v\n", err)
	}
	asReq, err := UnmarshalASReq(asreqData)
	if err != nil {
		t.Fatalf("AS REP Unmarshal error: %v\n", err)
	}
	t.Logf("AS REQ: %+v", asReq)
	assert.Equal(t, 5, asReq.PVNO, "PVNO not as expected")
	assert.Equal(t, 10, asReq.MsgType, "MsgType not as expected")
	assert.Equal(t, 1, asReq.ReqBody.CName.NameType, "Request body client name type not as expected")
	assert.Equal(t, "turnerj", asReq.ReqBody.CName.NameString[0], "Request body name string not as expected")
	assert.Equal(t, "JTLAN.CO.UK", asReq.ReqBody.Realm, "Request body realm not as expected")
	assert.Equal(t, 2, asReq.ReqBody.SName.NameType, "Request body service name type not as expected")
	assert.Equal(t, []string{"krbtgt", "JTLAN.CO.UK"}, asReq.ReqBody.SName.NameString, "Request body service name string not as expected")
	assert.IsType(t, time.Time{}, asReq.ReqBody.From, "From field in request body is not a time type")
	assert.IsType(t, time.Time{}, asReq.ReqBody.RTime, "Till field in request body is not a time type")
	assert.IsType(t, time.Time{}, asReq.ReqBody.RTime, "RTime field in request body is not a time type")
	assert.Equal(t, 2069991465, asReq.ReqBody.Nonce, "Nonce field in request body not as expected")
	assert.Equal(t, []int{18, 17, 16, 23, 25, 26}, asReq.ReqBody.EType, "Accepted EType field in request body not as expected")
}
