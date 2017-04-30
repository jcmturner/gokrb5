package messages

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/asn1tools"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/iana"
	"github.com/jcmturner/gokrb5/iana/adtype"
	"github.com/jcmturner/gokrb5/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/iana/errorcode"
	"github.com/jcmturner/gokrb5/iana/keyusage"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/mstypes"
	"github.com/jcmturner/gokrb5/pac"
	"github.com/jcmturner/gokrb5/types"
	"time"
)

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.3

type Ticket struct {
	TktVNO           int                 `asn1:"explicit,tag:0"`
	Realm            string              `asn1:"generalstring,explicit,tag:1"`
	SName            types.PrincipalName `asn1:"explicit,tag:2"`
	EncPart          types.EncryptedData `asn1:"explicit,tag:3"`
	DecryptedEncPart EncTicketPart       `asn1:"optional"` // Not part of ASN1 bytes so marked as optional so unmarshalling works
}

type EncTicketPart struct {
	Flags             asn1.BitString          `asn1:"explicit,tag:0"`
	Key               types.EncryptionKey     `asn1:"explicit,tag:1"`
	CRealm            string                  `asn1:"generalstring,explicit,tag:2"`
	CName             types.PrincipalName     `asn1:"explicit,tag:3"`
	Transited         TransitedEncoding       `asn1:"explicit,tag:4"`
	AuthTime          time.Time               `asn1:"generalized,explicit,tag:5"`
	StartTime         time.Time               `asn1:"generalized,explicit,optional,tag:6"`
	EndTime           time.Time               `asn1:"generalized,explicit,tag:7"`
	RenewTill         time.Time               `asn1:"generalized,explicit,optional,tag:8"`
	CAddr             types.HostAddresses     `asn1:"explicit,optional,tag:9"`
	AuthorizationData types.AuthorizationData `asn1:"explicit,optional,tag:10"`
}

type TransitedEncoding struct {
	TRType   int    `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

func NewTicket(cname types.PrincipalName, crealm string, sname types.PrincipalName, srealm string, flags asn1.BitString, sktab keytab.Keytab, eTypeID, kvno int, authTime, startTime, endTime, renewTill time.Time) (Ticket, types.EncryptionKey, error) {
	etype, err := crypto.GetEtype(eTypeID)
	if err != nil {
		return Ticket{}, types.EncryptionKey{}, err
	}
	ks := etype.GetKeyByteSize()
	kv := make([]byte, ks, ks)
	rand.Read(kv)
	sessionKey := types.EncryptionKey{
		KeyType:  eTypeID,
		KeyValue: kv,
	}
	etp := EncTicketPart{
		Flags:     flags,
		Key:       sessionKey,
		CRealm:    crealm,
		CName:     cname,
		Transited: TransitedEncoding{},
		AuthTime:  authTime,
		StartTime: startTime,
		EndTime:   endTime,
		RenewTill: renewTill,
	}
	b, err := asn1.Marshal(etp)
	b = asn1tools.AddASNAppTag(b, asnAppTag.EncTicketPart)
	skey, err := sktab.GetEncryptionKey(sname.NameString, srealm, kvno, eTypeID)
	if err != nil {
		return Ticket{}, types.EncryptionKey{}, err
	}
	ed, err := crypto.GetEncryptedData(b, skey, keyusage.KDC_REP_TICKET, kvno)
	tkt := Ticket{
		TktVNO:  iana.PVNO,
		Realm:   srealm,
		SName:   sname,
		EncPart: ed,
	}
	return tkt, sessionKey, nil
}

func (t *Ticket) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, t, fmt.Sprintf("application,explicit,tag:%d", asnAppTag.Ticket))
	return err
}

func (t *Ticket) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*t)
	if err != nil {
		return nil, err
	}
	b = asn1tools.AddASNAppTag(b, asnAppTag.Ticket)
	return b, nil
}

func (t *EncTicketPart) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, t, fmt.Sprintf("application,explicit,tag:%d", asnAppTag.EncTicketPart))
	return err
}

func UnmarshalTicket(b []byte) (t Ticket, err error) {
	_, err = asn1.UnmarshalWithParams(b, &t, fmt.Sprintf("application,explicit,tag:%d", asnAppTag.Ticket))
	return
}

func UnmarshalTicketsSequence(in asn1.RawValue) ([]Ticket, error) {
	//This is a workaround to a asn1 decoding issue in golang - https://github.com/golang/go/issues/17321. It's not pretty I'm afraid
	//We pull out raw values from the larger raw value (that is actually the data of the sequence of raw values) and track our position moving along the data.
	b := in.Bytes
	// Ignore the head of the asn1 stream (1 byte for tag and those for the length) as this is what tells us its a sequence but we're handling it ourselves
	p := 1 + asn1tools.GetNumberBytesInLengthHeader(in.Bytes)
	var tkts []Ticket
	var raw asn1.RawValue
	for p < (len(b)) {
		_, err := asn1.UnmarshalWithParams(b[p:], &raw, fmt.Sprintf("application,tag:%d", asnAppTag.Ticket))
		if err != nil {
			return nil, fmt.Errorf("Unmarshalling sequence of tickets failed geting length of ticket: %v", err)
		}
		t, err := UnmarshalTicket(b[p:])
		if err != nil {
			return nil, fmt.Errorf("Unmarshalling sequence of tickets failed: %v", err)
		}
		p += len(raw.FullBytes)
		tkts = append(tkts, t)
	}
	MarshalTicketSequence(tkts)
	return tkts, nil
}

func MarshalTicketSequence(tkts []Ticket) (asn1.RawValue, error) {
	raw := asn1.RawValue{
		Class:      2,
		IsCompound: true,
	}
	if len(tkts) < 1 {
		// There are no tickets to marshal
		return raw, nil
	}
	var btkts []byte
	for i, t := range tkts {
		b, err := t.Marshal()
		if err != nil {
			return raw, fmt.Errorf("Error marshalling ticket number %d in seqence of tickets", i+1)
		}
		btkts = append(btkts, b...)
	}
	// The ASN1 wrapping consists of 2 bytes:
	// 1st byte -> Identifier Octet - In this case an OCTET STRING (ASN TAG
	// 2nd byte -> The length (this will be the size indicated in the input bytes + 2 for the additional bytes we add here.
	// Application Tag:
	//| Byte:       | 8                            | 7                          | 6                                         | 5 | 4 | 3 | 2 | 1             |
	//| Value:      | 0                            | 1                          | 1                                         | From the RFC spec 4120        |
	//| Explanation | Defined by the ASN1 encoding rules for an application tag | A value of 1 indicates a constructed type | The ASN Application tag value |
	btkts = append(asn1tools.MarshalLengthBytes(len(btkts)), btkts...)
	btkts = append([]byte{byte(32 + asn1.TagSequence)}, btkts...)
	raw.Bytes = btkts
	// If we need to create teh full bytes then identifier octet is "context-specific" = 128 + "constructed" + 32 + the wrapping explicit tag (11)
	//fmt.Fprintf(os.Stderr, "mRaw fb: %v\n", raw.FullBytes)
	return raw, nil
}

func (t *Ticket) DecryptEncPart(keytab keytab.Keytab) error {
	key, err := keytab.GetEncryptionKey(t.SName.NameString, t.Realm, t.EncPart.KVNO, t.EncPart.EType)
	if err != nil {
		return NewKRBError(t.SName, t.Realm, errorcode.KRB_AP_ERR_NOKEY, fmt.Sprintf("Could not get key from keytab: %v", err))
	}
	b, err := crypto.DecryptEncPart(t.EncPart, key, keyusage.KDC_REP_TICKET)
	if err != nil {
		return fmt.Errorf("Error decrypting Ticket EncPart: %v", err)
	}
	var denc EncTicketPart
	err = denc.Unmarshal(b)
	if err != nil {
		return fmt.Errorf("Error unmarshalling encrypted part: %v", err)
	}
	t.DecryptedEncPart = denc
	return nil
}

func (t *Ticket) GetPACType(key types.EncryptionKey) (mstypes.PACType, error) {
	for _, ad := range t.DecryptedEncPart.AuthorizationData {
		if ad.ADType == adtype.AD_IF_RELEVANT {
			var ad2 types.AuthorizationData
			err := ad2.Unmarshal(ad.ADData)
			if err != nil {
				continue
			}
			// TODO note does tthe entry contain and AuthorizationData or AuthorizationDataEntry. Assuming the former atm.
			if ad2[0].ADType == adtype.AD_WIN2K_PAC {
				var p int
				var endian binary.ByteOrder = binary.LittleEndian
				pt := mstypes.Read_PACType(&ad2[0].ADData, &p, &endian)
				err = processAD_PAC(pt, ad2[0].ADData, key)
				return pt, err
			}
		}
	}
	return mstypes.PACType{}, errors.New("AuthorizationData within the ticket does not contain PAC data.")
}

// https://msdn.microsoft.com/en-us/library/cc237954.aspx
func processAD_PAC(pt mstypes.PACType, b []byte, key types.EncryptionKey) error {
	for _, buf := range pt.Buffers {
		p := make([]byte, buf.CBBufferSize, buf.CBBufferSize)
		copy(p, b[int(buf.Offset):int(buf.Offset)+int(buf.CBBufferSize)])
		switch int(buf.ULType) {
		case mstypes.ULTYPE_KERB_VALIDATION_INFO:
			var k pac.KerbValidationInfo
			err := k.Unmarshal(p)
			if err != nil {
				return err
			}
		case mstypes.ULTYPE_CREDENTIALS:
			var c pac.PAC_CredentialsInfo
			err := c.Unmarshal(p, key)
			if err != nil {
				return err
			}
		case mstypes.ULTYPE_PAC_SERVER_SIGNATURE_DATA:
			var k pac.PAC_SignatureData
			err := k.Unmarshal(p)
			if err != nil {
				return err
			}
		case mstypes.ULTYPE_PAC_KDC_SIGNATURE_DATA:
			var k pac.PAC_SignatureData
			err := k.Unmarshal(p)
			if err != nil {
				return err
			}
		case mstypes.ULTYPE_PAC_CLIENT_INFO:
			var k pac.PAC_ClientInfo
			err := k.Unmarshal(p)
			if err != nil {
				return err
			}
		case mstypes.ULTYPE_S4U_DELEGATION_INFO:
			var k pac.S4U_DelegationInfo
			err := k.Unmarshal(p)
			if err != nil {
				return err
			}
		case mstypes.ULTYPE_UPN_DNS_INFO:
			var k pac.UPN_DNSInfo
			err := k.Unmarshal(p)
			if err != nil {
				return err
			}
		case mstypes.ULTYPE_PAC_CLIENT_CLAIMS_INFO:
			var k pac.PAC_ClientClaimsInfo
			err := k.Unmarshal(p)
			if err != nil {
				return err
			}
		case mstypes.ULTYPE_PAC_DEVICE_INFO:
			var k pac.PAC_DeviceInfo
			err := k.Unmarshal(p)
			if err != nil {
				return err
			}
		case mstypes.ULTYPE_PAC_DEVICE_CLAIMS_INFO:
			var k pac.PAC_DeviceClaimsInfo
			err := k.Unmarshal(p)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
