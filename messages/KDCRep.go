package messages

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.4.2

import (
	"github.com/jcmturner/gokrb5/krb5types"
	"time"
	"encoding/asn1"
	"fmt"
	"github.com/jcmturner/gokrb5/krb5types/asnAppTag"
)

type marshalKDCRep struct {
	PVNO    int                     `asn1:"explicit,tag:0"`
	MsgType int                     `asn1:"explicit,tag:1"`
	PAData  []krb5types.PAData      `asn1:"explicit,optional,tag:2"`
	CRealm  string        `asn1:"explicit,tag:3"`
	CName   krb5types.PrincipalName `asn1:"explicit,tag:4"`
	// Ticket needs to be a raw value as it is wrapped in an APPLICATION tag
	Ticket  asn1.RawValue	        `asn1:"explicit,tag:5"`
	EncPart krb5types.EncryptedData `asn1:"explicit,tag:6"`
}

type marshalEncKDCRepPart struct {
	Key           krb5types.EncryptionKey `asn1:"explicit,tag:0"`
	LastReq       marshalLastReq                 `asn1:"explicit,tag:1"`
	Nonce         int                     `asn1:"explicit,tag:2"`
	KeyExpiration time.Time               `asn1:"explicit,optional,tag:3"`
	Flags         krb5types.TicketFlags   `asn1:"explicit,tag:4"`
	AuthTime      time.Time               `asn1:"explicit,tag:5"`
	StartTime     time.Time               `asn1:"explicit,optional,tag:6"`
	EndTime       time.Time               `asn1:"explicit,tag:7"`
	RenewTill     time.Time               `asn1:"explicit,optional,tag:8"`
	SRealm        string         `asn1:"explicit,tag:9"`
	SName         krb5types.PrincipalName `asn1:"explicit,tag:10"`
	CAddr         []krb5types.HostAddress `asn1:"explicit,optional,tag:11"`
}

type marshalLastReq struct {
	LRType  int       `asn1:"explicit,tag:0"`
	LRValue time.Time `asn1:"explicit,tag:1"`
}

type KDCRep struct {
	PVNO    int
	MsgType int
	PAData  []krb5types.PAData
	CRealm  string
	CName   krb5types.PrincipalName
	// Ticket needs to be a raw value as it is wrapped in an APPLICATION tag
	Ticket  krb5types.Ticket
	EncPart krb5types.EncryptedData
}

func UnmarshalASRep(b []byte) (k KDCRep, err error) {
	var asRep marshalKDCRep
	_, err = asn1.UnmarshalWithParams(b, &asRep, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.ASREP))
	if err != nil {
		return
	}
	//Process the raw ticket within
	k.Ticket, err = krb5types.UnmarshalTicket(asRep.Ticket.Bytes)
	if err != nil {
		return
	}
	k.PVNO = asRep.PVNO
	k.MsgType = asRep.MsgType
	k.PAData = asRep.PAData
	k.CRealm = asRep.CRealm
	k.CName = asRep.CName
	k.EncPart = asRep.EncPart
	return
}

