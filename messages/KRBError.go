package messages

import (
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/types"
	"github.com/jcmturner/gokrb5/types/asnAppTag"
	"time"
)

type KRBError struct {
	PVNO      int                 `asn1:"explicit,tag:0"`
	MsgType   int                 `asn1:"explicit,tag:1"`
	CTime     time.Time           `asn1:"generalized,optional,explicit,tag:2"`
	Cusec     int                 `asn1:"optional,explicit,tag:3"`
	STime     time.Time           `asn1:"generalized,explicit,tag:4"`
	Susec     int                 `asn1:"explicit,tag:5"`
	ErrorCode int                 `asn1:"explicit,tag:6"`
	CRealm    string              `asn1:"generalstring,optional,explicit,tag:7"`
	CName     types.PrincipalName `asn1:"optional,explicit,tag:8"`
	Realm     string              `asn1:"generalstring,explicit,tag:9"`
	SName     types.PrincipalName `asn1:"explicit,tag:10"`
	EText     string              `asn1:"generalstring,optional,explicit,tag:11"`
	EData     []byte              `asn1:"optional,explicit,tag:12"`
}

func (k *KRBError) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, k, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.KRBError))
	if err != nil {
		return err
	}
	expectedMsgType := types.KrbDictionary.MsgTypesByName["KRB_ERROR"]
	if k.MsgType != expectedMsgType {
		return fmt.Errorf("Message ID does not indicate a KRB_ERROR. Expected: %v; Actual: %v", expectedMsgType, k.MsgType)
	}
	return nil
}

func (k *KRBError) Error() string {
	return fmt.Sprintf("KRB Error: %d - %s", k.ErrorCode, k.EText)
}
