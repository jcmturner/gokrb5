package messages

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/types"
)

// APRep implements RFC 4120 KRB_AP_REP: https://tools.ietf.org/html/rfc4120#section-5.5.2.
type APRep struct {
	PVNO    int                 `asn1:"explicit,tag:0"`
	MsgType int                 `asn1:"explicit,tag:1"`
	EncPart types.EncryptedData `asn1:"explicit,tag:2"`
}

// EncAPRepPart is the encrypted part of KRB_AP_REP.
type EncAPRepPart struct {
	CTime          time.Time           `asn1:"generalized,explicit,tag:0"`
	Cusec          int                 `asn1:"explicit,tag:1"`
	Subkey         types.EncryptionKey `asn1:"optional,explicit,tag:2"`
	SequenceNumber int64               `asn1:"optional,explicit,tag:3"`
}

// Unmarshal bytes b into the APRep struct.
func (a *APRep) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, a, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.APREP))
	if err != nil {
		return processUnmarshalReplyError(b, err)
	}
	expectedMsgType := msgtype.KRB_AP_REP
	if a.MsgType != expectedMsgType {
		return krberror.NewErrorf(krberror.KRBMsgError, "message ID does not indicate a KRB_AP_REP. Expected: %v; Actual: %v", expectedMsgType, a.MsgType)
	}
	return nil
}

// Unmarshal bytes b into the APRep encrypted part struct.
func (a *EncAPRepPart) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, a, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.EncAPRepPart))
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "AP_REP unmarshal error")
	}
	return nil
}

func (a *EncAPRepPart) Marshal() ([]byte, error) {
	mk, err := asn1.Marshal(*a)
	if err != nil {
		return []byte{}, err
	}
	mk = asn1tools.AddASNAppTag(mk, asnAppTag.EncAPRepPart)
	return mk, nil
}

func (a *APRep) Marshal() ([]byte, error) {
	rep, err := asn1.Marshal(*a)
	if err != nil {
		return rep, err
	}
	rep = asn1tools.AddASNAppTag(rep, asnAppTag.APREP)
	return rep, nil
}

func (a *EncAPRepPart) GenerateSeqNumber() error {
	seq, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	if err != nil {
		return err
	}
	a.SequenceNumber = seq.Int64()
	return nil
}

func (a *APRep) DecryptEncryptedPart(sessionKey types.EncryptionKey) (EncAPRepPart, error) {
	encPart := EncAPRepPart{}

	ab, e := crypto.DecryptEncPart(a.EncPart, sessionKey, uint32(keyusage.AP_REP_ENCPART))
	if e != nil {
		return encPart, fmt.Errorf("error decrypting encrypted part: %v", e)
	}
	err := encPart.Unmarshal(ab)
	if err != nil {
		return encPart, fmt.Errorf("error unmarshaling encrypted part: %v", err)
	}
	return encPart, nil

}

func EncryptPart(tkt Ticket, sessionKey types.EncryptionKey, part EncAPRepPart) (types.EncryptedData, error) {
	var ed types.EncryptedData
	m, err := part.Marshal()
	if err != nil {
		return types.EncryptedData{}, krberror.Errorf(err, krberror.EncodingError, "marshaling error of EncryptedData form of APRep")
	}

	ed, err = crypto.GetEncryptedData(m, sessionKey, uint32(keyusage.AP_REP_ENCPART), tkt.EncPart.KVNO)
	if err != nil {
		return ed, krberror.Errorf(err, krberror.EncryptingError, "error encrypting APRepPart")
	}
	return ed, nil
}

func NewAPRep(tkt Ticket, authenticator types.Authenticator) (APRep, error) {
	part := EncAPRepPart{
		CTime: authenticator.CTime,
		Cusec: authenticator.Cusec,
	}
	err := part.GenerateSeqNumber()
	if err != nil {
		return APRep{}, err
	}
	part.Subkey = authenticator.SubKey

	ed, err := EncryptPart(tkt, tkt.DecryptedEncPart.Key, part)
	//ed, err := encryptPart(tkt, authenticator.SubKey, part)
	if err != nil {
		return APRep{}, err
	}

	a := APRep{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_AP_REP,
		EncPart: ed,
	}
	return a, nil
}
