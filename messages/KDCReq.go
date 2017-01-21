package messages

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.4.1

import (
	"encoding/asn1"
	"fmt"
	"github.com/jcmturner/gokrb5/types"
	"github.com/jcmturner/gokrb5/types/asnAppTag"
	"time"
)

type KDCReq struct {
	PVNO    int            `asn1:"explicit,tag:1"`
	MsgType int            `asn1:"explicit,tag:2"`
	PAData  []types.PAData `asn1:"explicit,optional,tag:3"`
	ReqBody KDCReqBody     `asn1:"explicit,tag:4"`
}

type marshalKDCReq struct {
	PVNO    int               `asn1:"explicit,tag:1"`
	MsgType int               `asn1:"explicit,tag:2"`
	PAData  []types.PAData    `asn1:"explicit,optional,tag:3"`
	ReqBody marshalKDCReqBody `asn1:"explicit,tag:4"`
}

type KDCReqBody struct {
	KDCOptions        asn1.BitString      `asn1:"explicit,tag:0"`
	CName             types.PrincipalName `asn1:"explicit,optional,tag:1"`
	Realm             string              `asn1:"explicit,tag:2"`
	SName             types.PrincipalName `asn1:"explicit,optional,tag:3"`
	From              time.Time           `asn1:"explicit,optional,tag:4"`
	Till              time.Time           `asn1:"explicit,tag:5"`
	RTime             time.Time           `asn1:"explicit,optional,tag:6"`
	Nonce             int                 `asn1:"explicit,tag:7"`
	EType             []int               `asn1:"explicit,tag:8"`
	Addresses         []types.HostAddress `asn1:"explicit,optional,tag:9"`
	EncAuthData       types.EncryptedData `asn1:"explicit,optional,tag:10"`
	AdditionalTickets []types.Ticket      `asn1:"explicit,optional,tag:11"`
}

type marshalKDCReqBody struct {
	KDCOptions  asn1.BitString      `asn1:"explicit,tag:0"`
	CName       types.PrincipalName `asn1:"explicit,optional,tag:1"`
	Realm       string              `asn1:"explicit,tag:2"`
	SName       types.PrincipalName `asn1:"explicit,optional,tag:3"`
	From        time.Time           `asn1:"explicit,optional,tag:4"`
	Till        time.Time           `asn1:"explicit,tag:5"`
	RTime       time.Time           `asn1:"explicit,optional,tag:6"`
	Nonce       int                 `asn1:"explicit,tag:7"`
	EType       []int               `asn1:"explicit,tag:8"`
	Addresses   []types.HostAddress `asn1:"explicit,optional,tag:9"`
	EncAuthData types.EncryptedData `asn1:"explicit,optional,tag:10"`
	// Ticket needs to be a raw value as it is wrapped in an APPLICATION tag
	AdditionalTickets asn1.RawValue `asn1:"explicit,optional,tag:11"`
}

func UnmarshalASReq(b []byte) (k KDCReq, err error) {
	k, err = unmarshalKDCReq(b, asnAppTag.ASREQ)
	if err != nil {
		return k, err
	}
	expectedMsgType := types.KrbDictionary.MsgTypesByName["KRB_AS_REQ"]
	if k.MsgType != expectedMsgType {
		return k, fmt.Errorf("Message ID does not indicate a KRB_AS_REQ. Expected: %v; Actual: %v", expectedMsgType, k.MsgType)
	}
	return k, nil
}

func unmarshalKDCReq(b []byte, asnAppTag int) (k KDCReq, err error) {
	var m marshalKDCReq
	//fmt.Fprintf(os.Stderr, "b: %+v\n", b)
	_, err = asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asnAppTag))
	if err != nil {
		err = fmt.Errorf("Error unmarshalling KDC_REQ: %v", err)
		return
	}
	//fmt.Fprintf(os.Stderr, "req: %+v", m)
	var reqb = KDCReqBody{
		KDCOptions:  m.ReqBody.KDCOptions,
		CName:       m.ReqBody.CName,
		Realm:       m.ReqBody.Realm,
		SName:       m.ReqBody.SName,
		From:        m.ReqBody.From,
		Till:        m.ReqBody.Till,
		RTime:       m.ReqBody.RTime,
		Nonce:       m.ReqBody.Nonce,
		EType:       m.ReqBody.EType,
		Addresses:   m.ReqBody.Addresses,
		EncAuthData: m.ReqBody.EncAuthData,
	}
	k.MsgType = m.MsgType
	k.PAData = m.PAData
	k.PVNO = m.PVNO
	if len(m.ReqBody.AdditionalTickets.Bytes) > 0 {
		reqb.AdditionalTickets, err = types.UnmarshalSequenceTickets(m.ReqBody.AdditionalTickets)
		if err != nil {
			return k, fmt.Errorf("Error unmarshalling additional tickets: %v", err)
		}
	}
	k.ReqBody = reqb
	return
}
