package messages

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

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
