package messages

import (
	"encoding/hex"
	"fmt"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/testdata"
	"github.com/jcmturner/gokrb5/types"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"os/user"
	"testing"
	"time"
)

func TestUnmarshalASRep(t *testing.T) {
	var a ASRep
	v := "encode_krb5_as_rep"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, types.KrbDictionary.MsgTypesByName["KRB_AS_REP"], a.MsgType, "MsgType not as expected")
	assert.Equal(t, 2, len(a.PAData), "Number of PAData items in the sequence not as expected")
	for i, pa := range a.PAData {
		assert.Equal(t, testdata.TEST_PADATA_TYPE, pa.PADataType, fmt.Sprintf("PAData type for entry %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue, fmt.Sprintf("PAData valye for entry %d not as expected", i+1))
	}
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "Client Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString), "SName in ticket does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString, "Ticket SName entries not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.Ticket.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.EncPart.KVNO, "Encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
}

func TestUnmarshalASRep_optionalsNULL(t *testing.T) {
	var a ASRep
	v := "encode_krb5_as_rep(optionalsNULL)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, types.KrbDictionary.MsgTypesByName["KRB_AS_REP"], a.MsgType, "MsgType not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "Client Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString), "SName in ticket does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString, "Ticket SName entries not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.Ticket.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.EncPart.KVNO, "Encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
}

func TestUnmarshalTGSRep(t *testing.T) {
	var a TGSRep
	v := "encode_krb5_tgs_rep"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, types.KrbDictionary.MsgTypesByName["KRB_TGS_REP"], a.MsgType, "MsgType not as expected")
	assert.Equal(t, 2, len(a.PAData), "Number of PAData items in the sequence not as expected")
	for i, pa := range a.PAData {
		assert.Equal(t, testdata.TEST_PADATA_TYPE, pa.PADataType, fmt.Sprintf("PAData type for entry %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue, fmt.Sprintf("PAData valye for entry %d not as expected", i+1))
	}
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "Client Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString), "SName in ticket does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString, "Ticket SName entries not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.Ticket.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.EncPart.KVNO, "Encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
}

func TestUnmarshalTGSRep_optionalsNULL(t *testing.T) {
	var a TGSRep
	v := "encode_krb5_tgs_rep(optionalsNULL)"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, testdata.TEST_KVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, types.KrbDictionary.MsgTypesByName["KRB_TGS_REP"], a.MsgType, "MsgType not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "Client Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString), "SName in ticket does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString, "Ticket SName entries not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.Ticket.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.EncPart.KVNO, "Encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
}

func TestUnmarshalEncKDCRepPart(t *testing.T) {
	var a EncKDCRepPart
	v := "encode_krb5_enc_kdc_rep_part"
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

	assert.Equal(t, 1, a.Key.KeyType, "Key type not as expected")
	assert.Equal(t, []byte("12345678"), a.Key.KeyValue, "Key value not as expected")
	assert.Equal(t, 2, len(a.LastReqs), "Number of last request entries not as expected")
	for i, r := range a.LastReqs {
		assert.Equal(t, -5, r.LRType, fmt.Sprintf("Last request typ not as expected for last request entry %d", i+1))
		assert.Equal(t, tt, r.LRValue, fmt.Sprintf("Last request time value not as expected for last request entry %d", i+1))
	}
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce, "Nonce not as expected")
	assert.Equal(t, tt, a.KeyExpiration, "key expiration time not as expected")
	assert.Equal(t, "fedcba98", hex.EncodeToString(a.Flags.Bytes), "Flags not as expected")
	assert.Equal(t, tt, a.AuthTime, "Auth time not as expected")
	assert.Equal(t, tt, a.StartTime, "Start time not as expected")
	assert.Equal(t, tt, a.EndTime, "End time not as expected")
	assert.Equal(t, tt, a.RenewTill, "Renew Till time not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.SRealm, "SRealm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.SName.NameType, "SName type not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "SName string entries not as expected")
	assert.Equal(t, 2, len(a.CAddr), "Number of client addresses not as expected")
	for i, addr := range a.CAddr {
		assert.Equal(t, 2, addr.AddrType, fmt.Sprintf("Host address type not as expected for address item %d", i+1))
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address), fmt.Sprintf("Host address not as expected for address item %d", i+1))
	}
}

func TestUnmarshalEncKDCRepPart_optionalsNULL(t *testing.T) {
	var a EncKDCRepPart
	v := "encode_krb5_enc_kdc_rep_part(optionalsNULL)"
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

	assert.Equal(t, 1, a.Key.KeyType, "Key type not as expected")
	assert.Equal(t, []byte("12345678"), a.Key.KeyValue, "Key value not as expected")
	assert.Equal(t, 2, len(a.LastReqs), "Number of last request entries not as expected")
	for i, r := range a.LastReqs {
		assert.Equal(t, -5, r.LRType, fmt.Sprintf("Last request typ not as expected for last request entry %d", i+1))
		assert.Equal(t, tt, r.LRValue, fmt.Sprintf("Last request time value not as expected for last request entry %d", i+1))
	}
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce, "Nonce not as expected")
	assert.Equal(t, "fe5cba98", hex.EncodeToString(a.Flags.Bytes), "Flags not as expected")
	assert.Equal(t, tt, a.AuthTime, "Auth time not as expected")
	assert.Equal(t, tt, a.EndTime, "End time not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.SRealm, "SRealm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMETYPE, a.SName.NameType, "SName type not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "SName string entries not as expected")
}

func TestUnmarshalASRepDecodeAndDecrypt(t *testing.T) {
	usr, _ := user.Current()
	dir := usr.HomeDir
	d, _ := os.Getwd()
	asrepData, err := ioutil.ReadFile(d + "/../testdata/AS-REP.raw")
	if err != nil {
		t.Fatalf("AS REP read error: %v\n", err)
	}
	var asRep ASRep
	err = asRep.Unmarshal(asrepData)
	if err != nil {
		t.Fatalf("AS REP Unmarshal error: %v\n", err)
	}
	assert.Equal(t, 5, asRep.PVNO, "PVNO not as expected")
	assert.Equal(t, 11, asRep.MsgType, "MsgType not as expected")
	assert.Equal(t, "JTLAN.CO.UK", asRep.CRealm, "Client Realm not as expected")
	assert.Equal(t, 1, asRep.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, "turnerj", asRep.CName.NameString[0], "CName NameType not as expected")
	assert.Equal(t, 19, asRep.PAData[0].PADataType, "PADataType not as expected")
	assert.Equal(t, 5, asRep.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, "JTLAN.CO.UK", asRep.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, 2, asRep.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, "krbtgt", asRep.Ticket.SName.NameString[0], "Ticket service name string not as expected")
	assert.Equal(t, "JTLAN.CO.UK", asRep.Ticket.SName.NameString[1], "Ticket service name string not as expected")
	assert.Equal(t, types.KrbDictionary.ETypesByName["aes256-cts-hmac-sha1-96"], asRep.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, 1, asRep.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, types.KrbDictionary.ETypesByName["aes256-cts-hmac-sha1-96"], asRep.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, 0, asRep.EncPart.KVNO, "Encrypted part KVNO not as expected")
	//t.Log("Finished testing unecrypted parts of AS REP")
	kt, err := keytab.Load(dir + "/tmp.keytab")
	if err != nil {
		fmt.Printf("keytab parse error: %v\n", err)
	}
	err = asRep.DecryptEncPart(kt)
	if err != nil {
		t.Fatalf("Decryption of EncPart failed: %v", err)
	}
	assert.Equal(t, 18, asRep.DecryptedEncPart.Key.KeyType, "KeyType in decrypted EncPart not as expected")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.LastReqs[0].LRValue, "LastReqs did not have a time value")
	assert.Equal(t, 2069991465, asRep.DecryptedEncPart.Nonce, "Nonce value not as expected")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.KeyExpiration, "Key expriation not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.AuthTime, "AuthTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.StartTime, "StartTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.EndTime, "StartTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.RenewTill, "RenewTill not a time type")
	assert.Equal(t, "JTLAN.CO.UK", asRep.DecryptedEncPart.SRealm, "Service realm not as expected")
	assert.Equal(t, 2, asRep.DecryptedEncPart.SName.NameType, "Name type for AS_REP not as expected")
	assert.Equal(t, []string{"krbtgt", "JTLAN.CO.UK"}, asRep.DecryptedEncPart.SName.NameString, "Service name string not as expected")
	//t.Log("Finished testing ecrypted parts of AS REP")

	//TODO should we be able to decrypt this part with the client key?
	/*s, err = etype.Decrypt(key, asRep.Ticket.EncPart.Cipher)
	if err != nil {
		t.Fatalf("Error decrypting ticket encrypted part: %v\n", err)
	}
	t.Logf("Decypted Ticket EncPart %+v", s)*/
}

//func TestKDCRep_Validate(t *testing.T) {
//	d, _ := os.Getwd()
//	asreqData, err := ioutil.ReadFile(d + "/../testdata/AS-REQ.raw")
//	if err != nil {
//		t.Fatalf("AS REP read error: %v\n", err)
//	}
//	asReq, err := UnmarshalASReq(asreqData)
//	if err != nil {
//		t.Fatalf("AS REP Unmarshal error: %v\n", err)
//	}
//
//	usr, _ := user.Current()
//	dir := usr.HomeDir
//	asrepData, err := ioutil.ReadFile(d + "/../testdata/AS-REP.raw")
//	if err != nil {
//		t.Fatalf("AS REP read error: %v\n", err)
//	}
//	var asRep ASRep
//	err = asRep.Unmarshal(asrepData)
//	if err != nil {
//		t.Fatalf("AS REP Unmarshal error: %v\n", err)
//	}
//	kt, err := keytab.Load(dir + "/tmp.keytab")
//	if err != nil {
//		fmt.Printf("keytab parse error: %v\n", err)
//	}
//	ok, err := asRep.Validate(asReq, kt)
//	if !ok || err != nil {
//		t.Fatalf("Validation of AS REP failed: %v", err)
//	}
//	t.Log("AS REP validation tests finished")
//}
