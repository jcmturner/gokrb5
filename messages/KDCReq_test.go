package messages

import (
	"encoding/hex"
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/testdata"
	"github.com/jcmturner/gokrb5/types"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestUnmarshalKDCReqBody(t *testing.T) {
	var a KDCReqBody
	v := "encode_krb5_kdc_req_body"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, "fedcba90", hex.EncodeToString(a.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.CName.NameType, "Request body CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "Request body CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "Request body CName entries not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Request body Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString), "Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "Request body SName entries not as expected")
	assert.Equal(t, tt, a.From, "Request body From time not as expected")
	assert.Equal(t, tt, a.Till, "Request body Till time not as expected")
	assert.Equal(t, tt, a.RTime, "Request body RTime time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int{0, 1}, a.EType, "Etype list not as expected")
	assert.Equal(t, 2, len(a.Addresses), "Number of client addresses not as expected")
	for i, addr := range a.Addresses {
		assert.Equal(t, 2, addr.AddrType, fmt.Sprintf("Host address type not as expected for address item %d", i+1))
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address), fmt.Sprintf("Host address not as expected for address item %d", i+1))
	}
	assert.Equal(t, testdata.TEST_ETYPE, a.EncAuthData.EType, "Etype of request body encrypted authorization data not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.EncAuthData.KVNO, "KVNO of request body encrypted authorization data not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncAuthData.Cipher, "Ciphertext of request body encrypted authorization data not as expected")
	assert.Equal(t, 2, len(a.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range a.AdditionalTickets {
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

func TestUnmarshalKDCReqBody_optionalsNULLexceptsecond_ticket(t *testing.T) {
	var a KDCReqBody
	v := "encode_krb5_kdc_req_body(optionalsNULLexceptsecond_ticket)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, "fedcba98", hex.EncodeToString(a.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Request body Realm not as expected")
	assert.Equal(t, tt, a.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int{0, 1}, a.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.EncAuthData.Cipher), "Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 2, len(a.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range a.AdditionalTickets {
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

func TestUnmarshalKDCReqBody_optionalsNULLexceptserver(t *testing.T) {
	var a KDCReqBody
	v := "encode_krb5_kdc_req_body(optionalsNULLexceptserver)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, "fedcba90", hex.EncodeToString(a.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Request body Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString), "Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "Request body SName entries not as expected")
	assert.Equal(t, tt, a.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int{0, 1}, a.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.EncAuthData.Cipher), "Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 0, len(a.AdditionalTickets), "Number of additional tickets not empty")
}

func TestUnmarshalASReq(t *testing.T) {
	var a ASReq
	v := "encode_krb5_as_req"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, types.KrbDictionary.MsgTypesByName["KRB_AS_REQ"], a.MsgType, "Message ID not as expected")
	assert.Equal(t, 2, len(a.PAData), "Number of PAData items in the sequence not as expected")
	for i, pa := range a.PAData {
		assert.Equal(t, testdata.TEST_PADATA_TYPE, pa.PADataType, fmt.Sprintf("PAData type for entry %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue, fmt.Sprintf("PAData valye for entry %d not as expected", i+1))
	}
	assert.Equal(t, "fedcba90", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.ReqBody.CName.NameType, "Request body CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.CName.NameString), "Request body CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.CName.NameString, "Request body CName entries not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm, "Request body Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.ReqBody.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.SName.NameString), "Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.SName.NameString, "Request body SName entries not as expected")
	assert.Equal(t, tt, a.ReqBody.From, "Request body From time not as expected")
	assert.Equal(t, tt, a.ReqBody.Till, "Request body Till time not as expected")
	assert.Equal(t, tt, a.ReqBody.RTime, "Request body RTime time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int{0, 1}, a.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 2, len(a.ReqBody.Addresses), "Number of client addresses not as expected")
	for i, addr := range a.ReqBody.Addresses {
		assert.Equal(t, 2, addr.AddrType, fmt.Sprintf("Host address type not as expected for address item %d", i+1))
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address), fmt.Sprintf("Host address not as expected for address item %d", i+1))
	}
	assert.Equal(t, testdata.TEST_ETYPE, a.ReqBody.EncAuthData.EType, "Etype of request body encrypted authorization data not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.ReqBody.EncAuthData.KVNO, "KVNO of request body encrypted authorization data not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.ReqBody.EncAuthData.Cipher, "Ciphertext of request body encrypted authorization data not as expected")
	assert.Equal(t, 2, len(a.ReqBody.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range a.ReqBody.AdditionalTickets {
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

func TestUnmarshalASReq_optionalsNULLexceptsecond_ticket(t *testing.T) {
	var a ASReq
	v := "encode_krb5_as_req(optionalsNULLexceptsecond_ticket)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, types.KrbDictionary.MsgTypesByName["KRB_AS_REQ"], a.MsgType, "Message ID not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, "fedcba98", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm, "Request body Realm not as expected")
	assert.Equal(t, tt, a.ReqBody.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int{0, 1}, a.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.ReqBody.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.ReqBody.EncAuthData.Cipher), "Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 2, len(a.ReqBody.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range a.ReqBody.AdditionalTickets {
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

func TestUnmarshalASReq_optionalsNULLexceptserver(t *testing.T) {
	var a ASReq
	v := "encode_krb5_as_req(optionalsNULLexceptserver)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, types.KrbDictionary.MsgTypesByName["KRB_AS_REQ"], a.MsgType, "Message ID not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, "fedcba90", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm, "Request body Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.ReqBody.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.SName.NameString), "Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.SName.NameString, "Request body SName entries not as expected")
	assert.Equal(t, tt, a.ReqBody.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int{0, 1}, a.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.ReqBody.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.ReqBody.EncAuthData.Cipher), "Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 0, len(a.ReqBody.AdditionalTickets), "Number of additional tickets not empty")
}

func TestUnmarshalTGSReq(t *testing.T) {
	var a TGSReq
	v := "encode_krb5_tgs_req"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, types.KrbDictionary.MsgTypesByName["KRB_TGS_REQ"], a.MsgType, "Message ID not as expected")
	assert.Equal(t, 2, len(a.PAData), "Number of PAData items in the sequence not as expected")
	for i, pa := range a.PAData {
		assert.Equal(t, testdata.TEST_PADATA_TYPE, pa.PADataType, fmt.Sprintf("PAData type for entry %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue, fmt.Sprintf("PAData valye for entry %d not as expected", i+1))
	}
	assert.Equal(t, "fedcba90", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.ReqBody.CName.NameType, "Request body CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.CName.NameString), "Request body CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.CName.NameString, "Request body CName entries not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm, "Request body Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.ReqBody.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.SName.NameString), "Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.SName.NameString, "Request body SName entries not as expected")
	assert.Equal(t, tt, a.ReqBody.From, "Request body From time not as expected")
	assert.Equal(t, tt, a.ReqBody.Till, "Request body Till time not as expected")
	assert.Equal(t, tt, a.ReqBody.RTime, "Request body RTime time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int{0, 1}, a.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 2, len(a.ReqBody.Addresses), "Number of client addresses not as expected")
	for i, addr := range a.ReqBody.Addresses {
		assert.Equal(t, 2, addr.AddrType, fmt.Sprintf("Host address type not as expected for address item %d", i+1))
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address), fmt.Sprintf("Host address not as expected for address item %d", i+1))
	}
	assert.Equal(t, testdata.TEST_ETYPE, a.ReqBody.EncAuthData.EType, "Etype of request body encrypted authorization data not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.ReqBody.EncAuthData.KVNO, "KVNO of request body encrypted authorization data not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.ReqBody.EncAuthData.Cipher, "Ciphertext of request body encrypted authorization data not as expected")
	assert.Equal(t, 2, len(a.ReqBody.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range a.ReqBody.AdditionalTickets {
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

func TestUnmarshalTGSReq_optionalsNULLexceptsecond_ticket(t *testing.T) {
	var a TGSReq
	v := "encode_krb5_tgs_req(optionalsNULLexceptsecond_ticket)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, types.KrbDictionary.MsgTypesByName["KRB_TGS_REQ"], a.MsgType, "Message ID not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, "fedcba98", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm, "Request body Realm not as expected")
	assert.Equal(t, tt, a.ReqBody.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int{0, 1}, a.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.ReqBody.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.ReqBody.EncAuthData.Cipher), "Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 2, len(a.ReqBody.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range a.ReqBody.AdditionalTickets {
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

func TestUnmarshalTGSReq_optionalsNULLexceptserver(t *testing.T) {
	var a TGSReq
	v := "encode_krb5_tgs_req(optionalsNULLexceptserver)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, types.KrbDictionary.MsgTypesByName["KRB_TGS_REQ"], a.MsgType, "Message ID not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, "fedcba90", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm, "Request body Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.ReqBody.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.SName.NameString), "Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.SName.NameString, "Request body SName entries not as expected")
	assert.Equal(t, tt, a.ReqBody.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int{0, 1}, a.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.ReqBody.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.ReqBody.EncAuthData.Cipher), "Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 0, len(a.ReqBody.AdditionalTickets), "Number of additional tickets not empty")
}

func TestUnmarshalASReq_raw(t *testing.T) {
	d, _ := os.Getwd()
	asreqData, err := ioutil.ReadFile(d + "/../testdata/AS-REQ.raw")
	if err != nil {
		t.Fatalf("AS REP read error: %v\n", err)
	}
	var asReq ASReq
	err = asReq.Unmarshal(asreqData)
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

//// Marshal Tests ////

func TestMarshalKDCReqBody(t *testing.T) {
	var a KDCReqBody
	v := "encode_krb5_kdc_req_body"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	a.KDCOptions.BitLength += 8
	a.KDCOptions.Bytes = append([]byte{byte(0)}, a.KDCOptions.Bytes...)
	mb, err := a.Marshal()
	if err != nil {
		t.Fatalf("Marshal of ticket errored: %v", err)
	}
	//a.KDCOptions.Bytes.BitLength += 8
	//a.KDCOptions.Bytes.Bytes = append([]byte{byte(0)}, a.KDCOptions.Bytes.Bytes...)
	//assert.Equal(t, b, mb, "Marshalled bytes not as expected")
	a.KDCOptions.BitLength = 40
	fmt.Fprintf(os.Stderr, " in: %v\nout: %v\n", b, mb)
	j, _ := asn1.Marshal(a.KDCOptions.Bytes)
	fmt.Fprintf(os.Stderr, "ib: %v\n j: %v\n", b[5:13], j)
	fmt.Fprintf(os.Stderr, "ib: %v\n j: %v\n", hex.EncodeToString(b[5:13]), hex.EncodeToString(j))
	fmt.Fprintf(os.Stderr, "bs: %+v", a.KDCOptions.Bytes)

}

func TestMarshalASReq(t *testing.T) {
	var a ASReq
	v := "encode_krb5_as_req"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	mb, err := a.Marshal()
	if err != nil {
		t.Fatalf("Marshal of ticket errored: %v", err)
	}
	assert.Equal(t, b, mb, "Marshalled bytes not as expected")
	fmt.Fprintf(os.Stderr, " in: %v\nout: %v", b, mb)
}
