package messages

import (
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/types"
	"github.com/jcmturner/gokrb5/types/asnAppTag"
	"time"
)

type KRBPriv struct {
	PVNO    int                 `asn1:"explicit,tag:0"`
	MsgType int                 `asn1:"explicit,tag:1"`
	EncPart types.EncryptedData `asn1:"explicit,tag:3"`
}

type EncKrbPrivPart struct {
	UserData       []byte            `asn1:"explicit,tag:0"`
	Timestamp      time.Time         `asn1:"optional,explicit,tag:1"`
	Usec           int               `asn1:"optional,explicit,tag:2"`
	SequenceNumber int               `asn1:"optional,explicit,tag:3"`
	SAddress       types.HostAddress `asn1:"explicit,tag:4"`
	RAddress       types.HostAddress `asn1:"optional,explicit,tag:5"`
}

func (k *KRBPriv) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, k, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.KRBPriv))
	if err != nil {
		return err
	}
	expectedMsgType := types.KrbDictionary.MsgTypesByName["KRB_PRIV"]
	if k.MsgType != expectedMsgType {
		return fmt.Errorf("Message ID does not indicate a KRB_PRIV. Expected: %v; Actual: %v", expectedMsgType, k.MsgType)
	}
	return nil
}

func (k *EncKrbPrivPart) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, k, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.EncKrbPrivPart))
	if err != nil {
		return err
	}
	return nil
}
