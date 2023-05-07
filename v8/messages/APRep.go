package messages

import (
	"fmt"
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

// Marshal the AP-REP message to a byte slice
func (a *APRep) Marshal() (b []byte, err error) {
	b, err = asn1.Marshal(*a)
	if err != nil {
		return
	}

	b = asn1tools.AddASNAppTag(b, asnAppTag.APREP)
	return
}

// Decrypt the encrypted part of the APRep message
func (a *APRep) DecryptEncPart(sessionKey types.EncryptionKey) (encpart EncAPRepPart, err error) {
	decrypted, err := crypto.DecryptEncPart(a.EncPart, sessionKey, uint32(keyusage.AP_REP_ENCPART))
	if err != nil {
		err = krberror.Errorf(err, krberror.DecryptingError, "error decrypting AP-REP enc-part")
		return
	}

	err = encpart.Unmarshal(decrypted)
	if err != nil {
		err = krberror.Errorf(err, krberror.EncodingError, "error unmarshalling decrypted AP-REP enc-part")
		return
	}

	return
}

// Marshal the encrypted part of the APRep message to a byte slice
func (a *EncAPRepPart) Marshal() (b []byte, err error) {
	b, err = asn1.Marshal(*a)
	if err != nil {
		return
	}

	b = asn1tools.AddASNAppTag(b, asnAppTag.EncAPRepPart)
	return
}

// Create a new APRep message with an encrypted enc-part
func NewAPRep(tkt Ticket, sessionKey types.EncryptionKey, encPart EncAPRepPart) (a APRep, err error) {
	m, err := encPart.Marshal()
	if err != nil {
		err = krberror.Errorf(err, krberror.EncodingError, "marshaling error of AP-REP enc-part")
		return
	}

	ed, err := crypto.GetEncryptedData(m, sessionKey, uint32(keyusage.AP_REP_ENCPART), tkt.EncPart.KVNO)
	if err != nil {
		err = krberror.Errorf(err, krberror.EncryptingError, "error encrypting AP-REP enc-part")
		return
	}

	a = APRep{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_AP_REP,
		EncPart: ed,
	}
	return
}

// Verify a decrypted APRep enc-part against an authenticator.  The authenticatror should be
// same as the one embedded in the APReq message that casused this APRep to be generated
func (a *EncAPRepPart) Verify(auth types.Authenticator) error {
	// check the response has the same time values as the request
	// Note - we can't use time.Equal() as m.clientCTime has a monotomic clock value and
	// which causes the equality to fail
	if !(a.CTime.Unix() == auth.CTime.Unix() && a.Cusec == auth.Cusec) {
		return fmt.Errorf("ap-rep time stamp does not match authenticator")
	}

	return nil
}
