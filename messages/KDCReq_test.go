package messages

import (
	"encoding/hex"
	"fmt"
	"github.com/jcmturner/gokrb5/testdata"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func unmarshalKDCReq_test(t *testing.T, v string) KDCReq {
	//t.Logf("Starting unmarshal tests of %s", v)
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("AS REQ read error: %v\n", err)
	}
	m, err := UnmarshalASReq(b)
	if err != nil {
		t.Fatalf("AS REQ Unmarshal error of %s: %v\n", v, err)
	}
	return m
}

func TestUnmarshalASReq_full(t *testing.T) {
	m := unmarshalKDCReq_test(t, "encode_krb5_as_req")
	assert.Equal(t, 2, len(m.PAData), "PAData does not have the expected number of entries")
	assert.Equal(t, 13, m.PAData[0].PADataType, "PADataType of first PAData entry is not as expected")
	assert.Equal(t, "pa-data", string(m.PAData[0].PADataValue), "PADataValue of first PAData entry is not as expected")
	assert.Equal(t, 13, m.PAData[1].PADataType, "PADataType of second PAData entry is not as expected")
	assert.Equal(t, "pa-data", string(m.PAData[1].PADataValue), "PADataValue of second PAData entry is not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, m.ReqBody.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(m.ReqBody.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, m.ReqBody.CName.NameString, "CName name strings not as expected")
}

func TestUnmarshalASReqDecode_optionalsNULLexceptsecond_ticket(t *testing.T) {
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	m := unmarshalKDCReq_test(t, "encode_krb5_as_req(optionalsNULLexceptsecond_ticket)")
	assert.Equal(t, testdata.TEST_KVNO, m.PVNO, "PVNO not as expected")
	assert.Equal(t, 10, m.MsgType, "MsgType not as expected")
	assert.Equal(t, "fedcba98", hex.EncodeToString(m.ReqBody.KDCOptions.Bytes), "KDCOptions in request body not as expected")
	assert.Equal(t, testdata.TEST_REALM, m.ReqBody.Realm, "Ticket Realm not as expected")
	assert.Equal(t, tt, m.ReqBody.Till, "Till time is not as expected")
	assert.Equal(t, testdata.TEST_NONCE, m.ReqBody.Nonce, "Nonce value is not as expected")
	assert.Equal(t, []int{0, 1}, m.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 2, len(m.ReqBody.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range m.ReqBody.AdditionalTickets {
		assert.Equal(t, testdata.TEST_KVNO, tkt.TktVNO, fmt.Sprintf("Additional ticket (%v) ticket-vno not as expected", i+1))
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm, fmt.Sprintf("Additional ticket (%v) realm not as expected", i+1))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, tkt.SName.NameType, fmt.Sprintf("Additional ticket (%v) SName NameType not as expected", i+1))
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString), fmt.Sprintf("Additional ticket (%v) SName does not have the expected number of NameStrings", i+1))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString, fmt.Sprintf("Additional ticket (%v) SName name string entries not as expected", i+1))
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType, fmt.Sprintf("Additional ticket (%v) encPart etype not as expected", i+1))
		assert.Equal(t, testdata.TEST_KVNO, tkt.EncPart.KVNO, fmt.Sprintf("Additional ticket (%v) encPart KVNO not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher, fmt.Sprintf("Additional ticket (%v) encPart cipher not as expected", i+1))
	}
}

func TestUnmarshalASReqDecode_optionalsNULLexceptserver(t *testing.T) {
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	m := unmarshalKDCReq_test(t, "encode_krb5_as_req(optionalsNULLexceptserver)")
	assert.Equal(t, testdata.TEST_KVNO, m.PVNO, "PVNO not as expected")
	assert.Equal(t, 10, m.MsgType, "MsgType not as expected")
	assert.Equal(t, "fedcba90", hex.EncodeToString(m.ReqBody.KDCOptions.Bytes), "KDCOptions in request body not as expected")
	assert.Equal(t, testdata.TEST_REALM, m.ReqBody.Realm, "Ticket Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, m.ReqBody.SName.NameType, "SName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(m.ReqBody.SName.NameString), "SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, m.ReqBody.SName.NameString, "SName entries not as expected")
	assert.Equal(t, tt, m.ReqBody.Till, "Till time is not as expected")
	assert.Equal(t, testdata.TEST_NONCE, m.ReqBody.Nonce, "Nonce value is not as expected")
	assert.Equal(t, []int{0, 1}, m.ReqBody.EType, "Etype list not as expected")
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
	//t.Logf("AS REQ: %+v", asReq)
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
