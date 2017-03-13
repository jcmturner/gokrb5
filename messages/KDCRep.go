package messages

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.4.2

import (
	"errors"
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/config"
	"github.com/jcmturner/gokrb5/credentials"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/iana/keyusage"
	"github.com/jcmturner/gokrb5/iana/msgtype"
	"github.com/jcmturner/gokrb5/iana/patype"
	"github.com/jcmturner/gokrb5/types"
	"time"
)

type marshalKDCRep struct {
	PVNO    int                  `asn1:"explicit,tag:0"`
	MsgType int                  `asn1:"explicit,tag:1"`
	PAData  types.PADataSequence `asn1:"explicit,optional,tag:2"`
	CRealm  string               `asn1:"generalstring,explicit,tag:3"`
	CName   types.PrincipalName  `asn1:"explicit,tag:4"`
	// Ticket needs to be a raw value as it is wrapped in an APPLICATION tag
	Ticket  asn1.RawValue       `asn1:"explicit,tag:5"`
	EncPart types.EncryptedData `asn1:"explicit,tag:6"`
}

type KDCRepFields struct {
	PVNO             int
	MsgType          int
	PAData           []types.PAData
	CRealm           string
	CName            types.PrincipalName
	Ticket           types.Ticket
	EncPart          types.EncryptedData
	DecryptedEncPart EncKDCRepPart
}

type ASRep struct {
	KDCRepFields
}
type TGSRep struct {
	KDCRepFields
}

type EncKDCRepPart struct {
	Key           types.EncryptionKey  `asn1:"explicit,tag:0"`
	LastReqs      []LastReq            `asn1:"explicit,tag:1"`
	Nonce         int                  `asn1:"explicit,tag:2"`
	KeyExpiration time.Time            `asn1:"generalized,explicit,optional,tag:3"`
	Flags         asn1.BitString       `asn1:"explicit,tag:4"`
	AuthTime      time.Time            `asn1:"generalized,explicit,tag:5"`
	StartTime     time.Time            `asn1:"generalized,explicit,optional,tag:6"`
	EndTime       time.Time            `asn1:"generalized,explicit,tag:7"`
	RenewTill     time.Time            `asn1:"generalized,explicit,optional,tag:8"`
	SRealm        string               `asn1:"generalstring,explicit,tag:9"`
	SName         types.PrincipalName  `asn1:"explicit,tag:10"`
	CAddr         []types.HostAddress  `asn1:"explicit,optional,tag:11"`
	EncPAData     types.PADataSequence `asn1:"explicit,optional,tag:12"`
}

type LastReq struct {
	LRType  int       `asn1:"explicit,tag:0"`
	LRValue time.Time `asn1:"generalized,explicit,tag:1"`
}

func (k *ASRep) Unmarshal(b []byte) error {
	var m marshalKDCRep
	_, err := asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.ASREP))
	if err != nil {
		return err
	}
	if m.MsgType != msgtype.KRB_AS_REP {
		return errors.New("Message ID does not indicate a KRB_AS_REP")
	}
	//Process the raw ticket within
	tkt, err := types.UnmarshalTicket(m.Ticket.Bytes)
	if err != nil {
		return err
	}
	k.KDCRepFields = KDCRepFields{
		PVNO:    m.PVNO,
		MsgType: m.MsgType,
		PAData:  m.PAData,
		CRealm:  m.CRealm,
		CName:   m.CName,
		Ticket:  tkt,
		EncPart: m.EncPart,
	}
	return nil
}

func (k *TGSRep) Unmarshal(b []byte) error {
	var m marshalKDCRep
	_, err := asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.TGSREP))
	if err != nil {
		return err
	}
	if m.MsgType != msgtype.KRB_TGS_REP {
		return errors.New("Message ID does not indicate a KRB_TGS_REP")
	}
	//Process the raw ticket within
	tkt, err := types.UnmarshalTicket(m.Ticket.Bytes)
	if err != nil {
		return err
	}
	k.KDCRepFields = KDCRepFields{
		PVNO:    m.PVNO,
		MsgType: m.MsgType,
		PAData:  m.PAData,
		CRealm:  m.CRealm,
		CName:   m.CName,
		Ticket:  tkt,
		EncPart: m.EncPart,
	}
	return nil
}

func (e *EncKDCRepPart) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, e, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.EncASRepPart))
	if err != nil {
		// Try using tag 26
		/* Ref: RFC 4120
		Compatibility note: Some implementations unconditionally send an
		encrypted EncTGSRepPart (application tag number 26) in this field
		regardless of whether the reply is a AS-REP or a TGS-REP.  In the
		interest of compatibility, implementors MAY relax the check on the
		tag number of the decrypted ENC-PART.*/
		_, err = asn1.UnmarshalWithParams(b, e, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.EncTGSRepPart))
		return err
	}
	return err
}

func (k *ASRep) DecryptEncPart(c *credentials.Credentials) error {
	var etype crypto.EType
	var key types.EncryptionKey
	var err error
	if c.HasKeytab() {
		etype, err = crypto.GetEtype(k.EncPart.EType)
		if err != nil {
			return fmt.Errorf("Error getting encryption type: %v", err)
		}
		key, err = c.Keytab.GetEncryptionKey(k.CName.NameString[0], k.CRealm, k.EncPart.KVNO, k.EncPart.EType)
		if err != nil {
			return fmt.Errorf("Could not get key from keytab: %v", err)
		}
	}
	if c.HasPassword() {
		key, etype, err = crypto.GetKeyFromPassword(c.Password, k.CName, k.CRealm, k.EncPart.EType, k.PAData)
		if err != nil {
			return fmt.Errorf("Could not derive key from password: %v", err)
		}
	}
	if !c.HasKeytab() && !c.HasPassword() {
		return errors.New("No secret available in credentials to preform decryption")
	}
	b, err := crypto.DecryptEncPart(key.KeyValue, k.EncPart, etype, keyusage.AS_REP_ENCPART)
	if err != nil {
		return fmt.Errorf("Error decrypting KDC_REP EncPart: %v", err)
	}
	var denc EncKDCRepPart
	err = denc.Unmarshal(b)
	if err != nil {
		return fmt.Errorf("Error unmarshalling encrypted part: %v", err)
	}
	k.DecryptedEncPart = denc
	return nil
}

func (k *ASRep) IsValid(cfg *config.Config, asReq ASReq) (bool, error) {
	//Ref RFC 4120 Section 3.1.5
	if k.CName.NameType != asReq.ReqBody.CName.NameType || k.CName.NameString == nil {
		return false, fmt.Errorf("CName in response does not match what was requested. Requested: %+v; Reply: %+v", asReq.ReqBody.CName, k.CName)
	}
	for i := range k.CName.NameString {
		if k.CName.NameString[i] != asReq.ReqBody.CName.NameString[i] {
			return false, fmt.Errorf("CName in response does not match what was requested. Requested: %+v; Reply: %+v", asReq.ReqBody.CName, k.CName)
		}
	}
	if k.CRealm != asReq.ReqBody.Realm {
		return false, fmt.Errorf("CRealm in response does not match what was requested. Requested: %s; Reply: %s", asReq.ReqBody.Realm, k.CRealm)
	}
	if k.DecryptedEncPart.Nonce != asReq.ReqBody.Nonce {
		return false, errors.New("Possible replay attack, nonce in response does not match that in request")
	}
	if k.DecryptedEncPart.SName.NameType != asReq.ReqBody.SName.NameType || k.DecryptedEncPart.SName.NameString == nil {
		return false, fmt.Errorf("SName in response does not match what was requested. Requested: %v; Reply: %v", asReq.ReqBody.SName, k.DecryptedEncPart.SName)
	}
	for i := range k.CName.NameString {
		if k.DecryptedEncPart.SName.NameString[i] != asReq.ReqBody.SName.NameString[i] {
			return false, fmt.Errorf("SName in response does not match what was requested. Requested: %+v; Reply: %+v", asReq.ReqBody.SName, k.DecryptedEncPart.SName)
		}
	}
	if k.DecryptedEncPart.SRealm != asReq.ReqBody.Realm {
		return false, fmt.Errorf("SRealm in response does not match what was requested. Requested: %s; Reply: %s", asReq.ReqBody.Realm, k.DecryptedEncPart.SRealm)
	}
	if len(asReq.ReqBody.Addresses) > 0 {
		//TODO compare if address list is the same
	}
	if time.Since(k.DecryptedEncPart.AuthTime) > cfg.LibDefaults.Clockskew || time.Until(k.DecryptedEncPart.AuthTime) > cfg.LibDefaults.Clockskew {
		return false, fmt.Errorf("Clock skew with KDC too large. Greater than %v seconds", cfg.LibDefaults.Clockskew.Seconds())
	}
	if asReq.PAData.Contains(patype.PA_REQ_ENC_PA_REP) {
		if len(k.DecryptedEncPart.EncPAData) < 2 || !k.DecryptedEncPart.EncPAData.Contains(patype.PA_FX_FAST) {
			return false, errors.New("KDC did not respond appropriately to FAST negotiation")
		}
		//TODO figure out how to check hash and put back
		//for _, pa := range k.DecryptedEncPart.EncPAData {
		//	if pa.PADataType == patype.PA_REQ_ENC_PA_REP {
		//		var pafast types.PAReqEncPARep
		//		err := pafast.Unmarshal(pa.PADataValue)
		//		if err != nil {
		//			return false, fmt.Errorf("KDC FAST negotiation response error, could not unmarshal PA_REQ_ENC_PA_REP: %v", err)
		//		}
		//		etype, err := crypto.GetChksumEtype(pafast.ChksumType)
		//		if err != nil {
		//			return false, fmt.Errorf("KDC FAST negotiation response error, %v", err)
		//		}
		//		ab, _ := asReq.Marshal()
		//		if !crypto.VerifyChecksum(k.DecryptedEncPart.Key.KeyValue, pafast.Chksum, ab, keyusage.KEY_USAGE_AS_REQ, etype) {
		//			return false, errors.New("KDC FAST negotiation response checksum invalid")
		//		}
		//	}
		//}
	}
	return true, nil
}

func (k *TGSRep) DecryptEncPart(key types.EncryptionKey) error {
	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return fmt.Errorf("Could not get etype: %v", err)
	}
	b, err := crypto.DecryptEncPart(key.KeyValue, k.EncPart, etype, keyusage.TGS_REP_ENCPART_SESSION_KEY)
	if err != nil {
		return fmt.Errorf("Error decrypting KDC_REP EncPart: %v", err)
	}
	var denc EncKDCRepPart
	err = denc.Unmarshal(b)
	if err != nil {
		return fmt.Errorf("Error unmarshalling encrypted part: %v", err)
	}
	k.DecryptedEncPart = denc
	return nil
}

func (k *TGSRep) IsValid(cfg *config.Config, tgsReq TGSReq) (bool, error) {
	if k.CName.NameType != tgsReq.ReqBody.CName.NameType || k.CName.NameString == nil {
		return false, fmt.Errorf("CName in response does not match what was requested. Requested: %+v; Reply: %+v", tgsReq.ReqBody.CName, k.CName)
	}
	for i := range k.CName.NameString {
		if k.CName.NameString[i] != tgsReq.ReqBody.CName.NameString[i] {
			return false, fmt.Errorf("CName in response does not match what was requested. Requested: %+v; Reply: %+v", tgsReq.ReqBody.CName, k.CName)
		}
	}
	if k.CRealm != tgsReq.ReqBody.Realm {
		return false, fmt.Errorf("CRealm in response does not match what was requested. Requested: %s; Reply: %s", tgsReq.ReqBody.Realm, k.CRealm)
	}
	if k.DecryptedEncPart.Nonce != tgsReq.ReqBody.Nonce {
		return false, errors.New("Possible replay attack, nonce in response does not match that in request")
	}
	if k.Ticket.SName.NameType != tgsReq.ReqBody.SName.NameType || k.Ticket.SName.NameString == nil {
		return false, fmt.Errorf("SName in response ticket does not match what was requested. Requested: %v; Reply: %v", tgsReq.ReqBody.SName, k.Ticket.SName)
	}
	for i := range k.Ticket.SName.NameString {
		if k.Ticket.SName.NameString[i] != tgsReq.ReqBody.SName.NameString[i] {
			return false, fmt.Errorf("SName in response ticket does not match what was requested. Requested: %+v; Reply: %+v", tgsReq.ReqBody.SName, k.Ticket.SName)
		}
	}
	if k.DecryptedEncPart.SName.NameType != tgsReq.ReqBody.SName.NameType || k.DecryptedEncPart.SName.NameString == nil {
		return false, fmt.Errorf("SName in response does not match what was requested. Requested: %v; Reply: %v", tgsReq.ReqBody.SName, k.DecryptedEncPart.SName)
	}
	for i := range k.CName.NameString {
		if k.DecryptedEncPart.SName.NameString[i] != tgsReq.ReqBody.SName.NameString[i] {
			return false, fmt.Errorf("SName in response does not match what was requested. Requested: %+v; Reply: %+v", tgsReq.ReqBody.SName, k.DecryptedEncPart.SName)
		}
	}
	if k.DecryptedEncPart.SRealm != tgsReq.ReqBody.Realm {
		return false, fmt.Errorf("SRealm in response does not match what was requested. Requested: %s; Reply: %s", tgsReq.ReqBody.Realm, k.DecryptedEncPart.SRealm)
	}
	if len(tgsReq.ReqBody.Addresses) > 0 {
		//TODO compare if address list is the same
	}
	if !tgsReq.Renewal && (time.Since(k.DecryptedEncPart.AuthTime) > cfg.LibDefaults.Clockskew || time.Until(k.DecryptedEncPart.AuthTime) > cfg.LibDefaults.Clockskew) {
		return false, fmt.Errorf("Clock skew with KDC too large. Greater than %v seconds", cfg.LibDefaults.Clockskew.Seconds())
	}
	return true, nil
}
