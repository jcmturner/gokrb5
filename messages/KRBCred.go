package messages

import (
	"encoding/asn1"
	"github.com/jcmturner/gokrb5/types"
	"time"
	"fmt"
	"github.com/jcmturner/gokrb5/types/asnAppTag"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/crypto"
	"errors"
)

type marshalKRBCred struct {
	PVNO    int                 `asn1:"explicit,tag:0"`
	MsgType int                 `asn1:"explicit,tag:1"`
	Tickets asn1.RawValue       `asn1:"explicit,tag:2"`
	EncPart types.EncryptedData `asn1:"explicit,tag:3"`
}

type KRBCred struct {
	PVNO             int
	MsgType          int
	Tickets          []types.Ticket
	EncPart          types.EncryptedData
	DecryptedEncPart EncKrbCredPart
}

type EncKrbCredPart struct {
	TicketInfo []KrbCredInfo     `asn1:"explicit,tag:0"`
	Nouce      int               `asn1:"optional,explicit,tag:1"`
	Timestamp  time.Time         `asn1:"optional,explicit,tag:2"`
	Usec       int               `asn1:"optional,explicit,tag:3"`
	SAddress   types.HostAddress `asn1:"optional,explicit,tag:4"`
	RAddress   types.HostAddress `asn1:"optional,explicit,tag:5"`
}

type KrbCredInfo struct {
	Key       types.EncryptionKey `asn1:"explicit,tag:0"`
	PRealm    string              `asn1:"generalstring,optional,explicit,tag:1"`
	PName     types.PrincipalName `asn1:"optional,explicit,tag:2"`
	Flags     asn1.BitString      `asn1:"optional,explicit,tag:3"`
	AuthTime  time.Time           `asn1:"optional,explicit,tag:4"`
	StartTime time.Time           `asn1:"optional,explicit,tag:5"`
	EndTime   time.Time           `asn1:"optional,explicit,tag:6"`
	RenewTill time.Time           `asn1:"optional,explicit,tag:7"`
	SRealm    string              `asn1:"optional,explicit,ia5,tag:8"`
	SName     types.PrincipalName `asn1:"optional,explicit,tag:9"`
	CAddr     types.HostAddresses `asn1:"optional,explicit,tag:10"`
}

func (k *KRBCred) Unmarshal(b []byte) error {
	var m marshalKRBCred
	_, err := asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.KRBCred))
	if err != nil {
		return fmt.Errorf("Error unmarshalling KDC_CRED: %v", err)
	}
	expectedMsgType := types.KrbDictionary.MsgTypesByName["KRB_CRED"]
	if m.MsgType != expectedMsgType {
		return fmt.Errorf("Message ID does not indicate a KRB_CRED. Expected: %v; Actual: %v", expectedMsgType, m.MsgType)
	}
	k.PVNO = m.PVNO
	k.MsgType = m.MsgType
	k.EncPart = m.EncPart
	if len(m.Tickets.Bytes) > 0 {
		k.Tickets, err = types.UnmarshalTicketsSequence(m.Tickets)
		if err != nil {
			return fmt.Errorf("Error unmarshalling tickets within KRB_CRED: %v", err)
		}
	}
	return nil
}

func (k *KRBCred) DecryptEncPart(kt keytab.Keytab) error {
	//TODO move this to the a method on the Encrypted data object and call that from here. update the KDCRep too
	//TODO create the etype based on the EType value in the EncPart and find the corresponding entry in the keytab
	//k.EncPart.EType
	var etype crypto.Aes256CtsHmacSha96
	//Derive the key
	//Key Usage Number: 3 - "AS-REP encrypted part (includes TGS session key or application session key), encrypted with the client key"
	key, err := etype.DeriveKey(kt.Entries[0].Key.KeyMaterial, crypto.GetUsageKe(3))
	// Strip off the checksum from the end
	//TODO should this check be moved to the Decrypt method?
	b, err := etype.Decrypt(key, k.EncPart.Cipher[:len(k.EncPart.Cipher)-etype.GetHMACBitLength()/8])
	//Verify checksum
	if !etype.VerifyChecksum(kt.Entries[0].Key.KeyMaterial, k.EncPart.Cipher, b, 3) {
		return errors.New("Error decrypting encrypted part: checksum verification failed")
	}
	//Remove the confounder bytes
	b = b[etype.GetConfounderByteSize():]
	if err != nil {
		return fmt.Errorf("Error decrypting encrypted part: %v", err)
	}
	err = k.DecryptedEncPart.Unmarshal(b)
	if err != nil {
		return fmt.Errorf("Error unmarshalling encrypted part: %v", err)
	}
	return nil
}

func (k *EncKrbCredPart) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, k, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.EncKrbCredPart))
	if err != nil {
		return fmt.Errorf("Error unmarshalling EncKrbCredPart: %v", err)
	}
	return nil
}