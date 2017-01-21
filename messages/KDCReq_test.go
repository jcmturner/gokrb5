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

const (
	tf      = "20060102150405"
	trealm  = "ATHENA.MIT.EDU"
	tcipher = "krbASN.1 test message"
)

func unmarshal(t *testing.T, v string) KDCReq {
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
	//Parse the test time value into a time.Time type
	//tt, _ := time.Parse(tf, "19940610060317")

	m := unmarshal(t, "encode_krb5_as_req")
	assert.Equal(t, 2, len(m.PAData), "PAData does not have the expected number of entries")
	assert.Equal(t, 13, m.PAData[0].PADataType, "PADataType of first PAData entry is not as expected")
	assert.Equal(t, "pa-data", string(m.PAData[0].PADataValue), "PADataValue of first PAData entry is not as expected")
	assert.Equal(t, 13, m.PAData[1].PADataType, "PADataType of second PAData entry is not as expected")
	assert.Equal(t, "pa-data", string(m.PAData[1].PADataValue), "PADataValue of second PAData entry is not as expected")
	assert.Equal(t, 1, m.ReqBody.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, 2, len(m.ReqBody.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, "hftsai", m.ReqBody.CName.NameString[0], "CName first entry not as expected")
	assert.Equal(t, "extra", m.ReqBody.CName.NameString[1], "CName second entry not as expected")
}

func TestUnmarshalASReqDecode_optionalsNULLexceptsecond_ticket(t *testing.T) {
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(tf, "19940610060317")

	m := unmarshal(t, "encode_krb5_as_req(optionalsNULLexceptsecond_ticket)")
	assert.Equal(t, 5, m.PVNO, "PVNO not as expected")
	assert.Equal(t, 10, m.MsgType, "MsgType not as expected")
	assert.Equal(t, "fedcba98", hex.EncodeToString(m.ReqBody.KDCOptions.Bytes), "KDCOptions in request body not as expected")
	assert.Equal(t, trealm, m.ReqBody.Realm, "Ticket Realm not as expected")
	assert.Equal(t, tt, m.ReqBody.Till, "Till time is not as expected")
	assert.Equal(t, 42, m.ReqBody.Nonce, "Nonce value is not as expected")
	assert.Equal(t, []int{0, 1}, m.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 2, len(m.ReqBody.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range m.ReqBody.AdditionalTickets {
		assert.Equal(t, 5, tkt.TktVNO, fmt.Sprintf("Additional ticket (%v) ticket-vno not as expected", i+1))
		assert.Equal(t, trealm, tkt.Realm, fmt.Sprintf("Additional ticket (%v) realm not as expected", i+1))
		assert.Equal(t, 1, tkt.SName.NameType, fmt.Sprintf("Additional ticket (%v) SName NameType not as expected", i+1))
		assert.Equal(t, 2, len(tkt.SName.NameString), fmt.Sprintf("Additional ticket (%v) SName does not have the expected number of NameStrings", i+1))
		assert.Equal(t, "hftsai", tkt.SName.NameString[0], fmt.Sprintf("Additional ticket (%v) SName first entry not as expected", i+1))
		assert.Equal(t, "extra", tkt.SName.NameString[1], fmt.Sprintf("Additional ticket (%v) SName second entry not as expected", i+1))
		assert.Equal(t, 0, tkt.EncPart.EType, fmt.Sprintf("Additional ticket (%v) encPart etype not as expected", i+1))
		assert.Equal(t, 5, tkt.EncPart.KVNO, fmt.Sprintf("Additional ticket (%v) encPart KVNO not as expected", i+1))
		assert.Equal(t, []byte(tcipher), tkt.EncPart.Cipher, fmt.Sprintf("Additional ticket (%v) encPart etype not as expected", i+1))
	}
}

func TestUnmarshalASReqDecode_optionalsNULLexceptserver(t *testing.T) {
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(tf, "19940610060317")

	m := unmarshal(t, "encode_krb5_as_req(optionalsNULLexceptserver)")
	assert.Equal(t, 5, m.PVNO, "PVNO not as expected")
	assert.Equal(t, 10, m.MsgType, "MsgType not as expected")
	assert.Equal(t, "fedcba90", hex.EncodeToString(m.ReqBody.KDCOptions.Bytes), "KDCOptions in request body not as expected")
	assert.Equal(t, trealm, m.ReqBody.Realm, "Ticket Realm not as expected")
	assert.Equal(t, 1, m.ReqBody.SName.NameType, "SName NameType not as expected")
	assert.Equal(t, 2, len(m.ReqBody.SName.NameString), "SName does not have the expected number of NameStrings")
	assert.Equal(t, "hftsai", m.ReqBody.SName.NameString[0], "SName first entry not as expected")
	assert.Equal(t, "extra", m.ReqBody.SName.NameString[1], "SName second entry not as expected")
	assert.Equal(t, tt, m.ReqBody.Till, "Till time is not as expected")
	assert.Equal(t, 42, m.ReqBody.Nonce, "Nonce value is not as expected")
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
