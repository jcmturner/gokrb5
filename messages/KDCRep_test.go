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

func TestUnmarshalASRepDecode(t *testing.T) {
	t.Log("Starting unmarshal tests of full AS REP")
	asrepData, err := hex.DecodeString(testdata.TestVectors["encode_krb5_as_rep"])
	if err != nil {
		t.Fatalf("AS REP read error: %v\n", err)
	}
	asRep, err := UnmarshalASRep(asrepData)
	if err != nil {
		t.Fatalf("AS REP Unmarshal error of encode_krb5_as_rep: %v\n", err)
	}
	assert.Equal(t, 5, asRep.PVNO, "PVNO not as expected")
	assert.Equal(t, 11, asRep.MsgType, "MsgType not as expected")
	assert.Equal(t, 2, len(asRep.PAData), "PAData does not have the expected number of entries")
	assert.Equal(t, 13, asRep.PAData[0].PADataType, "PADataType of first PAData entry is not as expected")
	assert.Equal(t, "pa-data", string(asRep.PAData[0].PADataValue), "PADataValue of first PAData entry is not as expected")
	assert.Equal(t, 13, asRep.PAData[1].PADataType, "PADataType of second PAData entry is not as expected")
	assert.Equal(t, "pa-data", string(asRep.PAData[1].PADataValue), "PADataValue of second PAData entry is not as expected")
	assert.Equal(t, "ATHENA.MIT.EDU", asRep.CRealm, "Client Realm not as expected")
	assert.Equal(t, 1, asRep.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, 2, len(asRep.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, "hftsai", asRep.CName.NameString[0], "CName first entry not as expected")
	assert.Equal(t, "extra", asRep.CName.NameString[1], "CName second entry not as expected")
	assert.Equal(t, 5, asRep.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, "ATHENA.MIT.EDU", asRep.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, 1, asRep.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, 2, len(asRep.Ticket.SName.NameString), "SName in ticket does not have the expected number of NameStrings")
	assert.Equal(t, "hftsai", asRep.Ticket.SName.NameString[0], "SName first entry not as expected")
	assert.Equal(t, "extra", asRep.Ticket.SName.NameString[1], "SName second entry not as expected")
	assert.Equal(t, 0, asRep.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, 5, asRep.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, "krbASN.1 test message", string(asRep.Ticket.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
	assert.Equal(t, 0, asRep.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, 5, asRep.EncPart.KVNO, "Encrypted part KVNO not as expected")
	assert.Equal(t, "krbASN.1 test message", string(asRep.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
	t.Log("Finished unmarshal tests of full AS REP")

	t.Log("Startung unmarshal tests of AS REP will null values for optional fields")
	asrepData, err = hex.DecodeString(testdata.TestVectors["encode_krb5_as_rep(optionalsNULL)"])
	if err != nil {
		t.Fatalf("AS REP read error: %v\n", err)
	}
	asRep, err = UnmarshalASRep(asrepData)
	if err != nil {
		t.Fatalf("AS REP Unmarshal error of encode_krb5_as_rep(optionalsNULL): %v\n", err)
	}
	assert.Equal(t, 5, asRep.PVNO, "PVNO not as expected")
	assert.Equal(t, 11, asRep.MsgType, "MsgType not as expected")
	assert.Equal(t, "ATHENA.MIT.EDU", asRep.CRealm, "Client Realm not as expected")
	assert.Equal(t, 1, asRep.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, 2, len(asRep.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, "hftsai", asRep.CName.NameString[0], "CName first entry not as expected")
	assert.Equal(t, "extra", asRep.CName.NameString[1], "CName second entry not as expected")
	assert.Equal(t, 5, asRep.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, "ATHENA.MIT.EDU", asRep.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, 1, asRep.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, 2, len(asRep.Ticket.SName.NameString), "SName in ticket does not have the expected number of NameStrings")
	assert.Equal(t, "hftsai", asRep.Ticket.SName.NameString[0], "SName first entry not as expected")
	assert.Equal(t, "extra", asRep.Ticket.SName.NameString[1], "SName second entry not as expected")
	assert.Equal(t, 0, asRep.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, 5, asRep.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, "krbASN.1 test message", string(asRep.Ticket.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
	assert.Equal(t, 0, asRep.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, 5, asRep.EncPart.KVNO, "Encrypted part KVNO not as expected")
	assert.Equal(t, "krbASN.1 test message", string(asRep.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
	t.Log("Finished unmarshal tests of AS REP will null values for optional fields")
}

func TestUnmarshalASRepDecodeAndDecrypt(t *testing.T) {
	usr, _ := user.Current()
	dir := usr.HomeDir
	d, _ := os.Getwd()
	asrepData, err := ioutil.ReadFile(d + "/../testdata/AS-REP.raw")
	if err != nil {
		t.Fatalf("AS REP read error: %v\n", err)
	}
	asRep, err := UnmarshalASRep(asrepData)
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
	t.Log("Finished testing unecrypted parts of AS REP")
	kt, err := keytab.Load(dir + "/tmp.keytab")
	if err != nil {
		fmt.Printf("keytab parse error: %v\n", err)
	}
	err = asRep.DecryptEncPart(kt)
	if err != nil {
		t.Fatalf("Decryption of EncPart failed: %v", err)
	}
	assert.Equal(t, 18, asRep.DecryptedPart.Key.KeyType, "KeyType in decrypted EncPart not as expected")
	assert.IsType(t, time.Time{}, asRep.DecryptedPart.LastReqs[0].LRValue, "LastReqs did not have a time value")
	assert.Equal(t, 2069991465, asRep.DecryptedPart.Nonce, "Nonce value not as expected")
	assert.IsType(t, time.Time{}, asRep.DecryptedPart.KeyExpiration, "Key expriation not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedPart.AuthTime, "AuthTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedPart.StartTime, "StartTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedPart.EndTime, "StartTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedPart.RenewTill, "RenewTill not a time type")
	assert.Equal(t, "JTLAN.CO.UK", asRep.DecryptedPart.SRealm, "Service realm not as expected")
	assert.Equal(t, 2, asRep.DecryptedPart.SName.NameType, "Name type for AS_REP not as expected")
	assert.Equal(t, []string{"krbtgt", "JTLAN.CO.UK"}, asRep.DecryptedPart.SName.NameString, "Service name string not as expected")
	t.Log("Finished testing ecrypted parts of AS REP")

	//TODO should we be able to decrypt this part with the client key?
	/*s, err = etype.Decrypt(key, asRep.Ticket.EncPart.Cipher)
	if err != nil {
		t.Fatalf("Error decrypting ticket encrypted part: %v\n", err)
	}
	t.Logf("Decypted Ticket EncPart %+v", s)*/
}

func TestKDCRep_Validate(t *testing.T) {
	d, _ := os.Getwd()
	asreqData, err := ioutil.ReadFile(d + "/../testdata/AS-REQ.raw")
	if err != nil {
		t.Fatalf("AS REP read error: %v\n", err)
	}
	asReq, err := UnmarshalASReq(asreqData)
	if err != nil {
		t.Fatalf("AS REP Unmarshal error: %v\n", err)
	}

	usr, _ := user.Current()
	dir := usr.HomeDir
	asrepData, err := ioutil.ReadFile(d + "/../testdata/AS-REP.raw")
	if err != nil {
		t.Fatalf("AS REP read error: %v\n", err)
	}
	asRep, err := UnmarshalASRep(asrepData)
	if err != nil {
		t.Fatalf("AS REP Unmarshal error: %v\n", err)
	}
	kt, err := keytab.Load(dir + "/tmp.keytab")
	if err != nil {
		fmt.Printf("keytab parse error: %v\n", err)
	}
	ok, err := asRep.Validate(asReq, kt)
	if !ok || err != nil {
		t.Fatalf("Validation of AS REP failed: %v", err)
	}
	t.Log("AS REP validation tests finished")
}
