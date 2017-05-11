package messages

import (
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/iana/msgtype"
	"github.com/jcmturner/gokrb5/krberror"
	"github.com/jcmturner/gokrb5/types"
	"time"
)

// RFC 4120 KRB_PRIV: https://tools.ietf.org/html/rfc4120#section-5.7.1.
type KRBPriv struct {
	PVNO    int                 `asn1:"explicit,tag:0"`
	MsgType int                 `asn1:"explicit,tag:1"`
	EncPart types.EncryptedData `asn1:"explicit,tag:3"`
}

// Encrypted part of KRB_PRIV.
type EncKrbPrivPart struct {
	UserData       []byte            `asn1:"explicit,tag:0"`
	Timestamp      time.Time         `asn1:"generalized,optional,explicit,tag:1"`
	Usec           int               `asn1:"optional,explicit,tag:2"`
	SequenceNumber int               `asn1:"optional,explicit,tag:3"`
	SAddress       types.HostAddress `asn1:"explicit,tag:4"`
	RAddress       types.HostAddress `asn1:"optional,explicit,tag:5"`
}

// Unmarshal bytes b into the KRBPriv struct.
func (k *KRBPriv) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, k, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.KRBPriv))
	if err != nil {
		return processUnmarshalReplyError(b, err)
	}
	expectedMsgType := msgtype.KRB_PRIV
	if k.MsgType != expectedMsgType {
		return krberror.NewErrorf(krberror.KRBMSG_ERROR, "Message ID does not indicate a KRB_PRIV. Expected: %v; Actual: %v", expectedMsgType, k.MsgType)
	}
	return nil
}

// Decrypt the encrypted part of a KRB_PRIV.
func (k *EncKrbPrivPart) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, k, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.EncKrbPrivPart))
	if err != nil {
		return krberror.Errorf(err, krberror.ENCODING_ERROR, "KRB_PRIV unmarshal error")
	}
	return nil
}
