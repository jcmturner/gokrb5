package krb5types

import (
	"time"
	"encoding/asn1"
	"fmt"
	"github.com/jcmturner/gokrb5/krb5types/asnAppTag"
)

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.3

type Ticket struct {
	TktVNO  int           `asn1:"explicit,tag:0"`
	Realm   string         `asn1:"explicit,tag:1"`
	SName   PrincipalName `asn1:"explicit,tag:2"`
	EncPart EncryptedData `asn1:"explicit,tag:3"`
}

type EncTicketPart struct {
	Flags             asn1.BitString       `asn1:"explicit,tag:0"`
	Key               EncryptionKey     `asn1:"explicit,tag:1"`
	CRealm            string             `asn1:"explicit,tag:2"`
	CName             PrincipalName     `asn1:"explicit,tag:3"`
	Transited         TransitedEncoding `asn1:"explicit,tag:4"`
	AuthTime          time.Time         `asn1:"explicit,tag:5"`
	StartTime         time.Time         `asn1:"explicit,optional,tag:6"`
	EndTime           time.Time         `asn1:"explicit,tag:7"`
	RenewTill         time.Time         `asn1:"explicit,optional,tag:8"`
	CAddr             HostAddress       `asn1:"explicit,optional,tag:9"`
	AuthorizationData AuthorizationData `asn1:"explicit,optional,tag:10"`
}

type TransitedEncoding struct {
	TRType   int    `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

func UnmarshalTicket(b []byte) (t Ticket, err error) {
	_, err = asn1.UnmarshalWithParams(b, &t, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.Ticket))
	return
}