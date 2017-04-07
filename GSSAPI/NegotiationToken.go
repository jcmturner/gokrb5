package GSSAPI

import (
	"errors"
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/config"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/types"
)

/*
https://msdn.microsoft.com/en-us/library/ms995330.aspx

NegotiationToken ::= CHOICE {
  negTokenInit    [0] NegTokenInit,  This is the Negotiation token sent from the client to the server.
  negTokenResp    [1] NegTokenResp
}

NegTokenInit ::= SEQUENCE {
  mechTypes       [0] MechTypeList,
  reqFlags        [1] ContextFlags  OPTIONAL,
  -- inherited from RFC 2478 for backward compatibility,
  -- RECOMMENDED to be left out
  mechToken       [2] OCTET STRING  OPTIONAL,
  mechListMIC     [3] OCTET STRING  OPTIONAL,
  ...
}

NegTokenResp ::= SEQUENCE {
  negState       [0] ENUMERATED {
    accept-completed    (0),
    accept-incomplete   (1),
    reject              (2),
    request-mic         (3)
  }                                 OPTIONAL,
  -- REQUIRED in the first reply from the target
  supportedMech   [1] MechType      OPTIONAL,
  -- present only in the first reply from the target
  responseToken   [2] OCTET STRING  OPTIONAL,
  mechListMIC     [3] OCTET STRING  OPTIONAL,
  ...
}
*/

// Negotiation Token - Init
type NegTokenInit struct {
	MechTypes    []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	ReqFlags     ContextFlags            `asn1:"explicit,optional,tag:1"`
	MechToken    []byte                  `asn1:"explicit,optional,tag:2"`
	MechTokenMIC []byte                  `asn1:"explicit,optional,tag:3"`
}

// Negotiation Token - Resp/Targ
type NegTokenResp struct {
	NegState      asn1.Enumerated       `asn1:"explicit,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"explicit,optional,tag:1"`
	ResponseToken []byte                `asn1:"explicit,optional,tag:2"`
	MechListMIC   []byte                `asn1:"explicit,optional,tag:3"`
}

type NegTokenTarg NegTokenResp

// Unmarshal and return either a NegTokenInit or a NegTokenResp.
//
// The boolean indicates if the response is a NegTokenInit.
// If error is nil and the boolean is false the response is a NegTokenResp.
func UnmarshalNegToken(b []byte) (bool, interface{}, error) {
	var a asn1.RawValue
	_, err := asn1.Unmarshal(b, &a)
	if err != nil {
		return false, nil, fmt.Errorf("Error unmarshalling NegotiationToken: %v", err)
	}
	switch a.Tag {
	case 0:
		var negToken NegTokenInit
		_, err = asn1.Unmarshal(a.Bytes, &negToken)
		if err != nil {
			return false, nil, fmt.Errorf("Error unmarshalling NegotiationToken type %d: %v", a.Tag, err)
		}
		return true, negToken, nil
	case 1:
		var negToken NegTokenResp
		_, err = asn1.Unmarshal(a.Bytes, &negToken)
		if err != nil {
			return false, nil, fmt.Errorf("Error unmarshalling NegotiationToken type %d: %v", a.Tag, err)
		}
		return false, negToken, nil
	default:
		return false, nil, errors.New("Unknown choice type for NegotiationToken")
	}

}

// Marshal an Init negotiation token
func (n *NegTokenInit) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*n)
	if err != nil {
		return nil, err
	}
	nt := asn1.RawValue{
		Tag:        0,
		Class:      2,
		IsCompound: true,
		Bytes:      b,
	}
	nb, err := asn1.Marshal(nt)
	if err != nil {
		return nil, err
	}
	return nb, nil
}

// Marshal a Resp/Targ negotiation token
func (n *NegTokenResp) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*n)
	if err != nil {
		return nil, err
	}
	nt := asn1.RawValue{
		Tag:        1,
		Class:      2,
		IsCompound: true,
		Bytes:      b,
	}
	nb, err := asn1.Marshal(nt)
	if err != nil {
		return nil, err
	}
	return nb, nil
}

// Create new Init negotiation token for Kerberos 5
func NewNegTokenInitKrb5(c config.Config, cname types.PrincipalName, tkt messages.Ticket, sessionKey types.EncryptionKey) (NegTokenInit, error) {
	mt, err := NewKRB5APREQMechToken(c, cname, tkt, sessionKey)
	if err != nil {
		return NegTokenInit{}, fmt.Errorf("Error getting MechToken; %v", err)
	}
	return NegTokenInit{
		MechTypes: []asn1.ObjectIdentifier{MechTypeOID_Krb5},
		MechToken: mt,
	}, nil
}
