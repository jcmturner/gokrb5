package messages

import (
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/iana/msgtype"
	"github.com/jcmturner/gokrb5/types"
	"time"
)

/*
KRB-SAFE        ::= [APPLICATION 20] SEQUENCE {
	pvno            [0] INTEGER (5),
	msg-type        [1] INTEGER (20),
	safe-body       [2] KRB-SAFE-BODY,
	cksum           [3] Checksum
}

KRB-SAFE-BODY   ::= SEQUENCE {
	user-data       [0] OCTET STRING,
	timestamp       [1] KerberosTime OPTIONAL,
	usec            [2] Microseconds OPTIONAL,
	seq-number      [3] UInt32 OPTIONAL,
	s-address       [4] HostAddress,
	r-address       [5] HostAddress OPTIONAL
}
*/

type KRBSafe struct {
	PVNO     int            `asn1:"explicit,tag:0"`
	MsgType  int            `asn1:"explicit,tag:1"`
	SafeBody KRBSafeBody    `asn1:"explicit,tag:2"`
	Cksum    types.Checksum `asn1:"explicit,tag:3"`
}

type KRBSafeBody struct {
	UserData       []byte            `asn1:"explicit,tag:0"`
	Timestamp      time.Time         `asn1:"generalized,optional,explicit,tag:1"`
	Usec           int               `asn1:"optional,explicit,tag:2"`
	SequenceNumber int               `asn1:"optional,explicit,tag:3"`
	SAddress       types.HostAddress `asn1:"explicit,tag:4"`
	RAddress       types.HostAddress `asn1:"optional,explicit,tag:5"`
}

func (s *KRBSafe) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, s, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.KRBSafe))
	if err != nil {
		return err
	}
	expectedMsgType := msgtype.KRB_SAFE
	if s.MsgType != expectedMsgType {
		return fmt.Errorf("Message ID does not indicate a KRB_SAFE. Expected: %v; Actual: %v", expectedMsgType, s.MsgType)
	}
	return nil
}
