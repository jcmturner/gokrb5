package messages

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.4.2

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/types"
	"github.com/jcmturner/gokrb5/types/asnAppTag"
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

type KDCRep struct {
	PVNO    int
	MsgType int
	PAData  []types.PAData
	CRealm  string
	CName   types.PrincipalName
	// Ticket needs to be a raw value as it is wrapped in an APPLICATION tag
	Ticket           types.Ticket
	EncPart          types.EncryptedData
	DecryptedEncPart EncKDCRepPart
}

type ASRep KDCRep
type TGSRep KDCRep

type EncKDCRepPart struct {
	Key           types.EncryptionKey `asn1:"explicit,tag:0"`
	LastReqs      []LastReq           `asn1:"explicit,tag:1"`
	Nonce         int                 `asn1:"explicit,tag:2"`
	KeyExpiration time.Time           `asn1:"generalized,explicit,optional,tag:3"`
	Flags         asn1.BitString      `asn1:"explicit,tag:4"`
	AuthTime      time.Time           `asn1:"generalized,explicit,tag:5"`
	StartTime     time.Time           `asn1:"generalized,explicit,optional,tag:6"`
	EndTime       time.Time           `asn1:"generalized,explicit,tag:7"`
	RenewTill     time.Time           `asn1:"generalized,explicit,optional,tag:8"`
	SRealm        string              `asn1:"generalstring,explicit,tag:9"`
	SName         types.PrincipalName `asn1:"explicit,tag:10"`
	CAddr         []types.HostAddress `asn1:"explicit,optional,tag:11"`
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
	if m.MsgType != types.KrbDictionary.MsgTypesByName["KRB_AS_REP"] {
		return errors.New("Message ID does not indicate a KRB_AS_REP")
	}
	//Process the raw ticket within
	k.Ticket, err = types.UnmarshalTicket(m.Ticket.Bytes)
	if err != nil {
		return err
	}
	k.PVNO = m.PVNO
	k.MsgType = m.MsgType
	k.PAData = m.PAData
	k.CRealm = m.CRealm
	k.CName = m.CName
	k.EncPart = m.EncPart
	return nil
}

func (k *TGSRep) Unmarshal(b []byte) error {
	var m marshalKDCRep
	_, err := asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.TGSREP))
	if err != nil {
		return err
	}
	if m.MsgType != types.KrbDictionary.MsgTypesByName["KRB_TGS_REP"] {
		return errors.New("Message ID does not indicate a KRB_TGS_REP")
	}
	//Process the raw ticket within
	k.Ticket, err = types.UnmarshalTicket(m.Ticket.Bytes)
	if err != nil {
		return err
	}
	k.PVNO = m.PVNO
	k.MsgType = m.MsgType
	k.PAData = m.PAData
	k.CRealm = m.CRealm
	k.CName = m.CName
	k.EncPart = m.EncPart
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

func (k *ASRep) DecryptTemp(passwd string) error {
	etype, _ := crypto.GetEtype(k.EncPart.EType)
	var et2 types.ETypeInfo2
	et2.Unmarshal(k.PAData[0].PADataValue)
	sk2p := etype.GetDefaultStringToKeyParams()
	if len(et2[0].S2KParams) == 8 {
		sk2p = hex.EncodeToString(et2[0].S2KParams)
	}
	key, err := etype.StringToKey(passwd, et2[0].Salt, sk2p)
	if err != nil {
		return fmt.Errorf("Error with string to key: %+v", et2)
	}
	b, err := crypto.DecryptEncPart(key, k.EncPart, etype, USAGE_AS_REP_ENCPART)
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

func (k *ASRep) DecryptEncPart(kt keytab.Keytab) error {
	etype, err := crypto.GetEtype(k.EncPart.EType)
	if err != nil {
		return fmt.Errorf("Error getting encryption type: %v", err)
	}
	var key []byte
	for _, pa := range k.PAData {
		if pa.PADataType == 19 {
			var et2 types.ETypeInfo2
			err := et2.Unmarshal(pa.PADataValue)
			if err != nil {
				return fmt.Errorf("Error unmashalling PA Data to PA-ETYPE-INFO2: %v", err)
			}
			etype, err := crypto.GetEtype(et2[0].EType)
			if err != nil {
				return fmt.Errorf("Error getting encryption type: %v", err)
			}
			sk2p := etype.GetDefaultStringToKeyParams()
			if len(et2[0].S2KParams) == 8 {
				sk2p = hex.EncodeToString(et2[0].S2KParams)
			}
			key, err = etype.StringToKey("TBA", et2[0].Salt, sk2p)
			if err != nil {
				return fmt.Errorf("Error with string to key: %+v", et2)
			}
		}
	}
	key, err = kt.GetKey(k.CName.NameString[0], k.CRealm, k.EncPart.KVNO, k.EncPart.EType)
	if err != nil {
		return fmt.Errorf("Could not get key from keytab: %v", err)
	}
	b, err := crypto.DecryptEncPart(key, k.EncPart, etype, USAGE_AS_REP_ENCPART)
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

func (k *TGSRep) DecryptEncPart(kt keytab.Keytab) error {
	etype, err := crypto.GetEtype(k.EncPart.EType)
	if err != nil {
		return fmt.Errorf("Keytab error: %v", err)
	}
	key, err := kt.GetKey(k.CName.NameString[0], k.CRealm, k.EncPart.KVNO, k.EncPart.EType)
	if err != nil {
		return fmt.Errorf("Could not get key from keytab: %v", err)
	}
	b, err := crypto.DecryptEncPart(key, k.EncPart, etype, USAGE_AS_REP_ENCPART)
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

// TODO put back after type tests complete to help me decide what to do with KDCRep vs ASRep and TGSRep
//func validateKDCRep(k *KDCRep, asReq KDCReq, kt keytab.Keytab) (bool, error) {
//	//Ref RFC 4120 Section 3.1.5
//	//TODO change the following to a contains check or slice compare
//	if k.CName.NameType != asReq.ReqBody.CName.NameType || k.CName.NameString[0] != asReq.ReqBody.CName.NameString[0] {
//		return false, fmt.Errorf("CName in response does not match what was requested. Requested: %v; Reply: %v", asReq.ReqBody.CName, k.CName)
//	}
//	if k.CRealm != asReq.ReqBody.Realm {
//		return false, fmt.Errorf("CRealm in response does not match what was requested. Requested: %s; Reply: %s", asReq.ReqBody.Realm, k.CRealm)
//	}
//	if k.DecryptedEncPart.Key.KeyType == 0 {
//		err := k.DecryptEncPart(kt)
//		if err != nil {
//			return false, fmt.Errorf("Could not decrypt encrypted part of response: %v", err)
//		}
//	}
//	if k.DecryptedEncPart.Nonce != asReq.ReqBody.Nonce {
//		return false, errors.New("Possible replay attack, nonce in request does not match that in response")
//	}
//	//TODO change the following to a contains check or slice compare
//	if k.DecryptedEncPart.SName.NameType != asReq.ReqBody.SName.NameType || k.DecryptedEncPart.SName.NameString[0] != asReq.ReqBody.SName.NameString[0] {
//		return false, fmt.Errorf("SName in response does not match what was requested. Requested: %v; Reply: %v", asReq.ReqBody.SName, k.DecryptedEncPart.SName)
//	}
//	if k.DecryptedEncPart.SRealm != asReq.ReqBody.Realm {
//		return false, fmt.Errorf("SRealm in response does not match what was requested. Requested: %s; Reply: %s", asReq.ReqBody.Realm, k.DecryptedEncPart.SRealm)
//	}
//	if len(asReq.ReqBody.Addresses) > 0 {
//		//TODO compare if address list is the same
//	}
//	return true, nil
//}
