package messages

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.4.1

import (
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/asn1tools"
	"github.com/jcmturner/gokrb5/config"
	"github.com/jcmturner/gokrb5/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/iana/msgtype"
	"github.com/jcmturner/gokrb5/types"
	"math/rand"
	"time"
)

type marshalKDCReq struct {
	PVNO    int                  `asn1:"explicit,tag:1"`
	MsgType int                  `asn1:"explicit,tag:2"`
	PAData  types.PADataSequence `asn1:"explicit,optional,tag:3"`
	ReqBody asn1.RawValue        `asn1:"explicit,tag:4"`
}

type KDCReq struct {
	PVNO    int            `asn1:"explicit,tag:1"`
	MsgType int            `asn1:"explicit,tag:2"`
	PAData  []types.PAData `asn1:"explicit,optional,tag:3"`
	ReqBody KDCReqBody     `asn1:"explicit,tag:4"`
}

type ASReq KDCReq
type TGSReq KDCReq

type marshalKDCReqBody struct {
	KDCOptions  asn1.BitString      `asn1:"explicit,tag:0"`
	CName       types.PrincipalName `asn1:"explicit,optional,tag:1"`
	Realm       string              `asn1:"generalstring,explicit,tag:2"`
	SName       types.PrincipalName `asn1:"explicit,optional,tag:3"`
	From        time.Time           `asn1:"generalized,explicit,optional,tag:4"`
	Till        time.Time           `asn1:"generalized,explicit,tag:5"`
	RTime       time.Time           `asn1:"generalized,explicit,optional,tag:6"`
	Nonce       int                 `asn1:"explicit,tag:7"`
	EType       []int               `asn1:"explicit,tag:8"`
	Addresses   []types.HostAddress `asn1:"explicit,optional,tag:9"`
	EncAuthData types.EncryptedData `asn1:"explicit,optional,tag:10"`
	// Ticket needs to be a raw value as it is wrapped in an APPLICATION tag
	AdditionalTickets asn1.RawValue `asn1:"explicit,optional,tag:11"`
}

type KDCReqBody struct {
	KDCOptions        asn1.BitString      `asn1:"explicit,tag:0"`
	CName             types.PrincipalName `asn1:"explicit,optional,tag:1"`
	Realm             string              `asn1:"generalstring,explicit,tag:2"`
	SName             types.PrincipalName `asn1:"explicit,optional,tag:3"`
	From              time.Time           `asn1:"generalized,explicit,optional,tag:4"`
	Till              time.Time           `asn1:"generalized,explicit,tag:5"`
	RTime             time.Time           `asn1:"generalized,explicit,optional,tag:6"`
	Nonce             int                 `asn1:"explicit,tag:7"`
	EType             []int               `asn1:"explicit,tag:8"`
	Addresses         []types.HostAddress `asn1:"explicit,optional,tag:9"`
	EncAuthData       types.EncryptedData `asn1:"explicit,optional,tag:10"`
	AdditionalTickets []types.Ticket      `asn1:"explicit,optional,tag:11"`
}

func NewASReq(c *config.Config, username string) ASReq {
	pas := types.PADataSequence{
		types.PAData{
			PADataType: types.PA_REQ_ENC_PA_REP,
		},
	}
	nonce := int(rand.Int31())
	t := time.Now()

	a := ASReq{
		PVNO:    PVNO,
		MsgType: KRB_AS_REQ,
		PAData:  pas,
		ReqBody: KDCReqBody{
			KDCOptions: c.LibDefaults.Kdc_default_options,
			Realm:      c.LibDefaults.Default_realm,
			CName: types.PrincipalName{
				NameType:   types.KRB_NT_PRINCIPAL,
				NameString: []string{username},
			},
			SName: types.PrincipalName{
				NameType:   types.KRB_NT_SRV_INST,
				NameString: []string{"krbtgt", c.LibDefaults.Default_realm},
			},
			Till:  t.Add(c.LibDefaults.Ticket_lifetime),
			Nonce: nonce,
			EType: c.LibDefaults.Default_tkt_enctype_ids,
		},
	}
	if c.LibDefaults.Forwardable {
		types.SetFlag(&a.ReqBody.KDCOptions, types.Forwardable)
	}
	if c.LibDefaults.Canonicalize {
		types.SetFlag(&a.ReqBody.KDCOptions, types.Canonicalize)
	}
	if c.LibDefaults.Proxiable {
		types.SetFlag(&a.ReqBody.KDCOptions, types.Proxiable)
	}
	if c.LibDefaults.Renew_lifetime != 0 {
		a.ReqBody.RTime = t.Add(c.LibDefaults.Renew_lifetime)
	}
	return a
}

func (k *ASReq) Unmarshal(b []byte) error {
	var m marshalKDCReq
	_, err := asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.ASREQ))
	if err != nil {
		return fmt.Errorf("Error unmarshalling KDC_REQ: %v", err)
	}
	expectedMsgType := msgtype.KRB_AS_REQ
	if m.MsgType != expectedMsgType {
		return fmt.Errorf("Message ID does not indicate a KRB_AS_REQ. Expected: %v; Actual: %v", expectedMsgType, m.MsgType)
	}
	var reqb KDCReqBody
	err = reqb.Unmarshal(m.ReqBody.Bytes)
	if err != nil {
		return fmt.Errorf("Error processing KDC_REQ_BODY: %v", err)
	}
	k.MsgType = m.MsgType
	k.PAData = m.PAData
	k.PVNO = m.PVNO
	k.ReqBody = reqb
	return nil
}

func (k *TGSReq) Unmarshal(b []byte) error {
	var m marshalKDCReq
	_, err := asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.TGSREQ))
	if err != nil {
		return fmt.Errorf("Error unmarshalling KDC_REQ: %v", err)
	}
	expectedMsgType := msgtype.KRB_TGS_REQ
	if m.MsgType != expectedMsgType {
		return fmt.Errorf("Message ID does not indicate a KRB_TGS_REQ. Expected: %v; Actual: %v", expectedMsgType, m.MsgType)
	}
	var reqb KDCReqBody
	err = reqb.Unmarshal(m.ReqBody.Bytes)
	if err != nil {
		return fmt.Errorf("Error processing KDC_REQ_BODY: %v", err)
	}
	k.MsgType = m.MsgType
	k.PAData = m.PAData
	k.PVNO = m.PVNO
	k.ReqBody = reqb
	return nil
}

func (k *KDCReqBody) Unmarshal(b []byte) error {
	var m marshalKDCReqBody
	_, err := asn1.Unmarshal(b, &m)
	if err != nil {
		return fmt.Errorf("Error unmarshalling KDC_REQ_BODY: %v", err)
	}
	k.KDCOptions = m.KDCOptions
	if len(k.KDCOptions.Bytes) < 4 {
		tb := make([]byte, 4-len(k.KDCOptions.Bytes))
		k.KDCOptions.Bytes = append(tb, k.KDCOptions.Bytes...)
		k.KDCOptions.BitLength = len(k.KDCOptions.Bytes) * 8
	}
	k.CName = m.CName
	k.Realm = m.Realm
	k.SName = m.SName
	k.From = m.From
	k.Till = m.Till
	k.RTime = m.RTime
	k.Nonce = m.Nonce
	k.EType = m.EType
	k.Addresses = m.Addresses
	k.EncAuthData = m.EncAuthData
	if len(m.AdditionalTickets.Bytes) > 0 {
		k.AdditionalTickets, err = types.UnmarshalTicketsSequence(m.AdditionalTickets)
		if err != nil {
			return fmt.Errorf("Error unmarshalling additional tickets: %v", err)
		}
	}
	return nil
}

func (k *ASReq) Marshal() ([]byte, error) {
	m := marshalKDCReq{
		PVNO:    k.PVNO,
		MsgType: k.MsgType,
		PAData:  k.PAData,
	}
	b, err := k.ReqBody.Marshal()
	if err != nil {
		var mk []byte
		return mk, err
	}
	m.ReqBody = asn1.RawValue{
		Class:      2,
		IsCompound: true,
		Tag:        4,
		Bytes:      b,
	}
	mk, err := asn1.Marshal(m)
	if err != nil {
		return mk, fmt.Errorf("Error marshalling AS_REQ: %v", err)
	}
	mk = asn1tools.AddASNAppTag(mk, asnAppTag.ASREQ)
	return mk, nil
}

func (k *TGSReq) Marshal() ([]byte, error) {
	m := marshalKDCReq{
		PVNO:    k.PVNO,
		MsgType: k.MsgType,
		PAData:  k.PAData,
	}
	b, err := k.ReqBody.Marshal()
	if err != nil {
		var mk []byte
		return mk, err
	}
	m.ReqBody = asn1.RawValue{
		Class:      2,
		IsCompound: true,
		Tag:        4,
		Bytes:      b,
	}
	mk, err := asn1.Marshal(m)
	if err != nil {
		return mk, fmt.Errorf("Error marshalling AS_REQ: %v", err)
	}
	mk = asn1tools.AddASNAppTag(mk, asnAppTag.TGSREQ)
	return mk, nil
}

func (k *KDCReqBody) Marshal() ([]byte, error) {
	var b []byte
	m := marshalKDCReqBody{
		KDCOptions:  k.KDCOptions,
		CName:       k.CName,
		Realm:       k.Realm,
		SName:       k.SName,
		From:        k.From,
		Till:        k.Till,
		RTime:       k.RTime,
		Nonce:       k.Nonce,
		EType:       k.EType,
		Addresses:   k.Addresses,
		EncAuthData: k.EncAuthData,
	}
	rawtkts, err := types.MarshalTicketSequence(k.AdditionalTickets)
	//The asn1.rawValue needs the tag setting on it for where it is in the KDCReqBody
	rawtkts.Tag = 11
	if err != nil {
		return b, fmt.Errorf("Error in marshalling KDC request body additional tickets: %v", err)
	}
	if len(rawtkts.Bytes) > 0 {
		m.AdditionalTickets = rawtkts
	}
	return asn1.Marshal(m)
}
