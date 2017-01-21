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
	PVNO    int                 `asn1:"explicit,tag:0"`
	MsgType int                 `asn1:"explicit,tag:1"`
	PAData  []types.PAData      `asn1:"explicit,optional,tag:2"`
	CRealm  string              `asn1:"explicit,tag:3"`
	CName   types.PrincipalName `asn1:"explicit,tag:4"`
	// Ticket needs to be a raw value as it is wrapped in an APPLICATION tag
	Ticket  asn1.RawValue       `asn1:"explicit,tag:5"`
	EncPart types.EncryptedData `asn1:"explicit,tag:6"`
}

type marshalEncKDCRepPart struct {
	Key           types.EncryptionKey `asn1:"explicit,tag:0"`
	LastReqs      []marshalLastReq    `asn1:"explicit,tag:1"`
	Nonce         int                 `asn1:"explicit,tag:2"`
	KeyExpiration time.Time           `asn1:"explicit,optional,tag:3"`
	Flags         asn1.BitString      `asn1:"explicit,tag:4"`
	AuthTime      time.Time           `asn1:"explicit,tag:5"`
	StartTime     time.Time           `asn1:"explicit,optional,tag:6"`
	EndTime       time.Time           `asn1:"explicit,tag:7"`
	RenewTill     time.Time           `asn1:"explicit,optional,tag:8"`
	SRealm        string              `asn1:"explicit,tag:9"`
	SName         types.PrincipalName `asn1:"explicit,tag:10"`
	CAddr         []types.HostAddress `asn1:"explicit,optional,tag:11"`
}

type marshalLastReq struct {
	LRType  int       `asn1:"explicit,tag:0"`
	LRValue time.Time `asn1:"explicit,tag:1"`
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
	DecryptedPart marshalEncKDCRepPart
}

func (k *KDCRep) DecryptEncPart(kt keytab.Keytab) error {
	//TODO create the etype based on the EType value in the EncPart and find the corresponding entry in the keytab
	//k.EncPart.EType
	var etype crypto.Aes256CtsHmacSha96
	//Derive the key
	//Key Usage Number: 3 - "AS-REP encrypted part (includes TGS session key or application session key), encrypted with the client key"
	key, err := etype.DeriveKey(kt.Entries[0].Key.KeyMaterial, crypto.GetUsageKe(3))
	// Strip off the checksum from the end
	//TODO should this check be moved to the Decrypt method?
	b, err := etype.Decrypt(key, k.EncPart.Cipher[:len(k.EncPart.Cipher)-etype.GetHMACBitLength()/8])
	//Verify checksum
	if !etype.VerifyChecksum(kt.Entries[0].Key.KeyMaterial, k.EncPart.Cipher, b, 3) {
		return errors.New("Error decrypting encrypted part: checksum verification failed")
	}
	//Remove the confounder bytes
	b = b[etype.GetConfounderByteSize():]
	if err != nil {
		return fmt.Errorf("Error decrypting encrypted part: %v", err)
	}
	_, err = asn1.UnmarshalWithParams(b, &k.DecryptedPart, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.EncASRepPart))
	if err != nil {
		// Try using tag 26
		/* Ref: RFC 4120
		Compatibility note: Some implementations unconditionally send an
		encrypted EncTGSRepPart (application tag number 26) in this field
		regardless of whether the reply is a AS-REP or a TGS-REP.  In the
		interest of compatibility, implementors MAY relax the check on the
		tag number of the decrypted ENC-PART.*/
		_, err = asn1.UnmarshalWithParams(b, &k.DecryptedPart, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.EncTGSRepPart))
		if err != nil {
			return fmt.Errorf("Error unmarshalling encrypted part: %v", err)
		}
	}
	return nil
}

func UnmarshalASRep(b []byte) (k KDCRep, err error) {
	k, err = unmarshalKDCRep(b, asnAppTag.ASREP)
	if err != nil {
		return k, err
	}
	if k.MsgType != types.KrbDictionary.MsgTypesByName["KRB_AS_REP"] {
		return k, errors.New("Message ID does not indicate a KRB_TGS_REP")
	}
	return k, nil
}

func UnmarshalTGSRep(b []byte) (k KDCRep, err error) {
	k, err = unmarshalKDCRep(b, asnAppTag.TGSREP)
	if err != nil {
		return k, err
	}
	if k.MsgType != types.KrbDictionary.MsgTypesByName["KRB_TGS_REP"] {
		return k, errors.New("Message ID does not indicate a KRB_TGS_REP")
	}
	return k, nil
}

func unmarshalKDCRep(b []byte, asnAppTag int) (k KDCRep, err error) {
	var asRep marshalKDCRep
	_, err = asn1.UnmarshalWithParams(b, &asRep, fmt.Sprintf("application,explicit,tag:%v", asnAppTag))
	if err != nil {
		return
	}
	//Process the raw ticket within
	k.Ticket, err = types.UnmarshalTicket(asRep.Ticket.Bytes)
	if err != nil {
		return
	}
	k.PVNO = asRep.PVNO
	k.MsgType = asRep.MsgType
	k.PAData = asRep.PAData
	k.CRealm = asRep.CRealm
	k.CName = asRep.CName
	k.EncPart = asRep.EncPart
	return
}

func (k KDCRep) Validate(asReq KDCReq, kt keytab.Keytab) (bool, error) {
	//Ref RFC 4120 Section 3.1.5
	//TODO change the following to a contains check or slice compare
	if k.CName.NameType != asReq.ReqBody.CName.NameType || k.CName.NameString[0] != asReq.ReqBody.CName.NameString[0] {
		return false, fmt.Errorf("CName in response does not match what was requested. Requested: %v; Reply: %v", asReq.ReqBody.CName, k.CName)
	}
	if k.CRealm != asReq.ReqBody.Realm {
		return false, fmt.Errorf("CRealm in response does not match what was requested. Requested: %s; Reply: %s", asReq.ReqBody.Realm, k.CRealm)
	}
	if k.DecryptedPart.Key.KeyType == 0 {
		err := k.DecryptEncPart(kt)
		if err != nil {
			return false, fmt.Errorf("Could not decrypt encrypted part of response: %v", err)
		}
	}
	if k.DecryptedPart.Nonce != asReq.ReqBody.Nonce {
		return false, errors.New("Possible replay attack, nonce in request does not match that in response")
	}
	//TODO change the following to a contains check or slice compare
	if k.DecryptedPart.SName.NameType != asReq.ReqBody.SName.NameType || k.DecryptedPart.SName.NameString[0] != asReq.ReqBody.SName.NameString[0] {
		return false, fmt.Errorf("SName in response does not match what was requested. Requested: %v; Reply: %v", asReq.ReqBody.SName, k.DecryptedPart.SName)
	}
	if k.DecryptedPart.SRealm != asReq.ReqBody.Realm {
		return false, fmt.Errorf("SRealm in response does not match what was requested. Requested: %s; Reply: %s", asReq.ReqBody.Realm, k.DecryptedPart.SRealm)
	}
	if len(asReq.ReqBody.Addresses) > 0 {
		//TODO compare if address list is the same
	}
	return true, nil
}
