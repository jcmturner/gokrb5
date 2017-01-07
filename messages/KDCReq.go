package messages

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.4.1

import (
	"encoding/asn1"
	"github.com/jcmturner/gokrb5/krb5types"
	"time"
	"fmt"
	"github.com/jcmturner/gokrb5/krb5types/asnAppTag"
)

type KDCReq struct {
	PVNO    int                `asn1:"explicit,tag:1"`
	MsgType int                `asn1:"explicit,tag:2"`
	PAData  []krb5types.PAData `asn1:"explicit,general,tag:3"`
	ReqBody KDCReqBody         `asn1:"explicit,tag:4"`
}

type KDCReqBody struct {
	KDCOptions        asn1.BitString          `asn1:"explicit,tag:0"`
	CName             krb5types.PrincipalName `asn1:"explicit,optional,tag:1"`
	Realm             string         `asn1:"explicit,tag:2"`
	SName             krb5types.PrincipalName `asn1:"explicit,optional,tag:3"`
	From              time.Time               `asn1:"explicit,optional,tag:4"`
	Till              time.Time               `asn1:"explicit,tag:5"`
	RTime             time.Time               `asn1:"explicit,optional,tag:6"`
	Nonce             int                     `asn1:"explicit,tag:7"`
	EType             []int                   `asn1:"explicit,tag:8"`
	Address           []krb5types.HostAddress `asn1:"explicit,optional,tag:9"`
	EncAuthData       krb5types.EncryptedData `asn1:"explicit,optional,tag:10"`
	AdditionalTickets []krb5types.Ticket      `asn1:"explicit,optional,tag:11"`
}

func UnmarshalASReq(b []byte) (k KDCReq, err error) {
	_, err = asn1.UnmarshalWithParams(b, &k, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.ASREQ))
	return
}