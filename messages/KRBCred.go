package messages

import (
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/iana/keyusage"
	"github.com/jcmturner/gokrb5/iana/msgtype"
	"github.com/jcmturner/gokrb5/types"
	"time"
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
	Timestamp  time.Time         `asn1:"generalized,optional,explicit,tag:2"`
	Usec       int               `asn1:"optional,explicit,tag:3"`
	SAddress   types.HostAddress `asn1:"optional,explicit,tag:4"`
	RAddress   types.HostAddress `asn1:"optional,explicit,tag:5"`
}

type KrbCredInfo struct {
	Key       types.EncryptionKey `asn1:"explicit,tag:0"`
	PRealm    string              `asn1:"generalstring,optional,explicit,tag:1"`
	PName     types.PrincipalName `asn1:"optional,explicit,tag:2"`
	Flags     asn1.BitString      `asn1:"optional,explicit,tag:3"`
	AuthTime  time.Time           `asn1:"generalized,optional,explicit,tag:4"`
	StartTime time.Time           `asn1:"generalized,optional,explicit,tag:5"`
	EndTime   time.Time           `asn1:"generalized,optional,explicit,tag:6"`
	RenewTill time.Time           `asn1:"generalized,optional,explicit,tag:7"`
	SRealm    string              `asn1:"optional,explicit,ia5,tag:8"`
	SName     types.PrincipalName `asn1:"optional,explicit,tag:9"`
	CAddr     types.HostAddresses `asn1:"optional,explicit,tag:10"`
}

func (k *KRBCred) Unmarshal(b []byte) error {
	var m marshalKRBCred
	_, err := asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.KRBCred))
	if err != nil {
		return fmt.Errorf("Error unmarshalling KDC_CRED: %v", processReplyError(b, err))
	}
	expectedMsgType := msgtype.KRB_CRED
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

func (k *KRBCred) DecryptEncPart(key types.EncryptionKey) error {
	b, err := crypto.DecryptEncPart(k.EncPart, key, keyusage.KRB_CRED_ENCPART)
	if err != nil {
		return fmt.Errorf("Error decrypting KDC_REP EncPart: %v", err)
	}
	var denc EncKrbCredPart
	err = denc.Unmarshal(b)
	if err != nil {
		return fmt.Errorf("Error unmarshalling encrypted part: %v", err)
	}
	k.DecryptedEncPart = denc
	return nil
}

func (k *EncKrbCredPart) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, k, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.EncKrbCredPart))
	if err != nil {
		return fmt.Errorf("Error unmarshalling EncKrbCredPart: %v", err)
	}
	return nil
}
