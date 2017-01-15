package messages

import (
"github.com/stretchr/testify/assert"
"testing"
	"io/ioutil"
	"fmt"
	"github.com/jcmturner/gokrb5/krb5types"
	"github.com/jcmturner/gokrb5/keytab"
)


func TestUnmarshalASRep(t *testing.T) {
	asrepData, _ := ioutil.ReadFile("/home/turnerj/IdeaProjects/golang/src/github.com/jcmturner/gokrb5/AS-REP.raw")
	asRep, err := UnmarshalASRep(asrepData)
	if err != nil {
		t.Fatalf("AS REP Unmarshal error: %v\n", err)
	}
	fmt.Printf("AS REP: %+v\n\n", asRep)
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
	assert.Equal(t, krb5types.KrbDictionary.ETypesByName["aes256-cts-hmac-sha1-96"], asRep.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, 1, asRep.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, krb5types.KrbDictionary.ETypesByName["aes256-cts-hmac-sha1-96"], asRep.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, 0, asRep.EncPart.KVNO, "Encrypted part KVNO not as expected")
	t.Log("Finished testing unecrypted parts of AS REP")

	kt, err := keytab.Load("/home/turnerj/tmp.keytab")
	if err != nil {
		fmt.Printf("keytab parse error: %v\n", err)
	}
	err = asRep.DecryptEncPart(kt)
	if err != nil {
		t.Fatalf("Decryption of EncPart failed: %v", err)
	}

	t.Logf("Decypted EncPart %+v", asRep.DecryptedPart)

	//TODO should we be able to decrypt this part with the client key?
	/*s, err = etype.Decrypt(key, asRep.Ticket.EncPart.Cipher)
	if err != nil {
		t.Fatalf("Error decrypting ticket encrypted part: %v\n", err)
	}
	t.Logf("Decypted Ticket EncPart %+v", s)*/
}

