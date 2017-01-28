package messages

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.4.2

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/types"
	"github.com/jcmturner/gokrb5/types/asnAppTag"
	"time"
)

type marshalKDCRep struct {
	PVNO             int                 `asn1:"explicit,tag:0"`
	MsgType          int                 `asn1:"explicit,tag:1"`
	PAData           types.PADataSequence     `asn1:"explicit,optional,tag:2"`
	CRealm           string              `asn1:"generalstring,explicit,tag:3"`
	CName            types.PrincipalName `asn1:"explicit,tag:4"`
	// Ticket needs to be a raw value as it is wrapped in an APPLICATION tag
	Ticket           asn1.RawValue       `asn1:"explicit,tag:5"`
	EncPart          types.EncryptedData `asn1:"explicit,tag:6"`
}

type KDCRep struct {
	PVNO    int
	MsgType int
	PAData  []types.PAData
	CRealm  string
	CName   types.PrincipalName
	// Ticket needs to be a raw value as it is wrapped in an APPLICATION tag
	Ticket        types.Ticket
	EncPart       types.EncryptedData
	DecryptedEncPart EncKDCRepPart
}

type ASRep KDCRep
type TGSRep KDCRep

type EncKDCRepPart struct {
	Key           types.EncryptionKey `asn1:"explicit,tag:0"`
	LastReqs      []LastReq    `asn1:"explicit,tag:1"`
	Nonce         int                 `asn1:"explicit,tag:2"`
	KeyExpiration time.Time           `asn1:"explicit,optional,tag:3"`
	Flags         asn1.BitString      `asn1:"explicit,tag:4"`
	AuthTime      time.Time           `asn1:"explicit,tag:5"`
	StartTime     time.Time           `asn1:"explicit,optional,tag:6"`
	EndTime       time.Time           `asn1:"explicit,tag:7"`
	RenewTill     time.Time           `asn1:"explicit,optional,tag:8"`
	SRealm        string              `asn1:"generalstring,explicit,tag:9"`
	SName         types.PrincipalName `asn1:"explicit,tag:10"`
	CAddr         []types.HostAddress `asn1:"explicit,optional,tag:11"`
}

type LastReq struct {
	LRType  int       `asn1:"explicit,tag:0"`
	LRValue time.Time `asn1:"explicit,tag:1"`
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

func decryptKDCRepEncPart(ct []byte, kt keytab.Keytab) (EncKDCRepPart, error) {
	//TODO move this to the a method on the Encrypted data object and call that from here. update the KRB_CRED too
	//TODO create the etype based on the EType value in the EncPart and find the corresponding entry in the keytab
	//k.EncPart.EType
	var etype crypto.Aes256CtsHmacSha96
	//Derive the key
	//Key Usage Number: 3 - "AS-REP encrypted part (includes TGS session key or application session key), encrypted with the client key"
	key, err := etype.DeriveKey(kt.Entries[0].Key.KeyMaterial, crypto.GetUsageKe(3))
	// Strip off the checksum from the end
	//TODO should this check be moved to the Decrypt method?
	b, err := etype.Decrypt(key, ct[:len(ct)-etype.GetHMACBitLength()/8])
	//Verify checksum
	var denc EncKDCRepPart
	if !etype.VerifyChecksum(kt.Entries[0].Key.KeyMaterial, ct, b, 3) {
		return denc, errors.New("Error decrypting encrypted part: checksum verification failed")
	}
	//Remove the confounder bytes
	b = b[etype.GetConfounderByteSize():]
	if err != nil {
		return denc, fmt.Errorf("Error decrypting encrypted part: %v", err)
	}
	err = denc.Unmarshal(b)
	if err != nil {
		return denc, fmt.Errorf("Error unmarshalling encrypted part: %v", err)
	}
	return denc, nil
}

func (k *ASRep) DecryptEncPart(kt keytab.Keytab) error {
	denc, err := decryptKDCRepEncPart(k.EncPart.Cipher, kt)
	if err != nil {
		return err
	}
	k.DecryptedEncPart = denc
	return nil
}

func (k *TGSRep) DecryptEncPart(kt keytab.Keytab) error {
	denc, err := decryptKDCRepEncPart(k.EncPart.Cipher, kt)
	if err != nil {
		return err
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
