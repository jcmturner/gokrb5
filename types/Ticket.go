package types

import (
	"encoding/asn1"
	"fmt"
	"github.com/jcmturner/gokrb5/types/asnAppTag"
	jtasn1 "github.com/jcmturner/asn1"
	"time"
	"os"
	"encoding/hex"
)

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.3

type Ticket struct {
	TktVNO  int           `asn1:"explicit,tag:0"`
	Realm   string        `asn1:"generalstring,explicit,tag:1"`
	SName   PrincipalName `asn1:"explicit,tag:2"`
	EncPart EncryptedData `asn1:"explicit,tag:3"`
}

type EncTicketPart struct {
	Flags             asn1.BitString    `asn1:"explicit,tag:0"`
	Key               EncryptionKey     `asn1:"explicit,tag:1"`
	CRealm            string            `asn1:"generalstring,explicit,tag:2"`
	CName             PrincipalName     `asn1:"explicit,tag:3"`
	Transited         TransitedEncoding `asn1:"explicit,tag:4"`
	AuthTime          time.Time         `asn1:"explicit,tag:5"`
	StartTime         time.Time         `asn1:"explicit,optional,tag:6"`
	EndTime           time.Time         `asn1:"explicit,tag:7"`
	RenewTill         time.Time         `asn1:"explicit,optional,tag:8"`
	CAddr             HostAddresses     `asn1:"explicit,optional,tag:9"`
	AuthorizationData AuthorizationData `asn1:"explicit,optional,tag:10"`
}

type TransitedEncoding struct {
	TRType   int    `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

func (t *Ticket) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, t, fmt.Sprintf("application,explicit,tag:%d", asnAppTag.Ticket))
	return err
}

func (t *Ticket) Marshal() ([]byte, error) {
	b, err := jtasn1.Marshal(*t)
	if err != nil {
		return nil, err
	}
	b = asnAppTag.AddASNAppTag(b, asnAppTag.Ticket)
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
	fmt.Fprintf(os.Stderr, "Raw c: %v is: %v t: %v\n", in.Class, in.IsCompound, in.Tag)
	fmt.Fprintf(os.Stderr, "Raw  b: %v\n", in.Bytes)
	fmt.Fprintf(os.Stderr, "Raw  b: %v\n", hex.EncodeToString(in.Bytes))
	fmt.Fprintf(os.Stderr, "Raw fb: %v\n", in.FullBytes)
	//This is a workaround to a asn1 decoding issue in golang - https://github.com/golang/go/issues/17321. It's not pretty I'm afraid
	//We pull out raw values from the larger raw value (that is actually the data of the sequence of raw values) and track our position moving along the data.
	b := in.Bytes
	// Ignore the head of the asn1 stream (3bytes) as this is what tells us its a sequence but we're handling it ourselves
	p := 3
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
		//Tag: 11,
	}
	var btkts []byte
	for i, t := range tkts {
		b, err := t.Marshal()
		if err != nil {
			return raw, fmt.Errorf("Error marshalling ticket number %d in seqence of tickets", i +1)
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
	btkts = append([]byte{byte(len(btkts))}, btkts...)
	fmt.Fprintf(os.Stderr, "mar: %+v", btkts)
	raw.Bytes = btkts
	return raw, nil
}
