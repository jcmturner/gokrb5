package messages

import (
	"errors"
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/types"
	"github.com/jcmturner/gokrb5/types/asnAppTag"
)

/*AP-REQ          ::= [APPLICATION 14] SEQUENCE {
pvno            [0] INTEGER (5),
msg-type        [1] INTEGER (14),
ap-options      [2] APOptions,
ticket          [3] Ticket,
authenticator   [4] EncryptedData -- Authenticator
}

APOptions       ::= KerberosFlags
-- reserved(0),
-- use-session-key(1),
-- mutual-required(2)*/

type marshalAPReq struct {
	PVNO      int            `asn1:"explicit,tag:0"`
	MsgType   int            `asn1:"explicit,tag:1"`
	APOptions asn1.BitString `asn1:"explicit,tag:2"`
	// Ticket needs to be a raw value as it is wrapped in an APPLICATION tag
	Ticket        asn1.RawValue       `asn1:"explicit,tag:3"`
	Authenticator types.EncryptedData `asn1:"explicit,tag:4"`
}

type APReq struct {
	PVNO          int                 `asn1:"explicit,tag:0"`
	MsgType       int                 `asn1:"explicit,tag:1"`
	APOptions     asn1.BitString      `asn1:"explicit,tag:2"`
	Ticket        types.Ticket        `asn1:"explicit,tag:3"`
	Authenticator types.EncryptedData `asn1:"explicit,tag:4"`
}

func (a *APReq) Unmarshal(b []byte) error {
	var m marshalAPReq
	_, err := asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.APREQ))
	if err != nil {
		return err
	}
	if m.MsgType != types.KrbDictionary.MsgTypesByName["KRB_AP_REQ"] {
		return errors.New("Message ID does not indicate a KRB_AS_REP")
	}
	a.PVNO = m.PVNO
	a.MsgType = m.MsgType
	a.APOptions = m.APOptions
	a.Authenticator = m.Authenticator
	a.Ticket, err = types.UnmarshalTicket(m.Ticket.Bytes)
	if err != nil {
		return fmt.Errorf("Error unmarshalling ticket in AP_REQ; %v", err)
	}
	return nil
}
