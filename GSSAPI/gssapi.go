package GSSAPI

import (
	"errors"
	"fmt"
	"github.com/jcmturner/asn1"
)

const (
	SPNEGO_OIDHex = "2b0601050502" //1.3.6.1.5.5.2
)

type SPNEGO struct {
	Init         bool
	Resp         bool
	NegTokenInit NegTokenInit
	NegTokenResp NegTokenResp
}

func (s *SPNEGO) Unmarshal(b []byte) error {
	var r []byte
	var err error
	if b[0] != byte(161) {
		// Not a NegTokenResp/Targ could be a NegTokenInit
		var oid asn1.ObjectIdentifier
		r, err = asn1.UnmarshalWithParams(b, &oid, fmt.Sprintf("application,explicit,tag:%v", 0))
		if err != nil {
			return fmt.Errorf("Not a valid SPNEGO token: %v", err)
		}
		// Check the OID is the SPNEGO OID value
		if !oid.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}) {
			return errors.New("OID does not match SPNEGO OID 1.3.6.1.5.5.2")
		}
	} else {
		// Could be a NegTokenResp/Targ
		r = b
	}

	var a asn1.RawValue
	_, err = asn1.Unmarshal(r, &a)
	if err != nil {
		return fmt.Errorf("Error unmarshalling SPNEGO: %v", err)
	}
	switch a.Tag {
	case 0:
		_, err = asn1.Unmarshal(a.Bytes, &s.NegTokenInit)
		if err != nil {
			return fmt.Errorf("Error unmarshalling NegotiationToken type %d: %v", a.Tag, err)
		}
		s.Init = true
	case 1:
		_, err = asn1.Unmarshal(a.Bytes, &s.NegTokenResp)
		if err != nil {
			return fmt.Errorf("Error unmarshalling NegotiationToken type %d: %v", a.Tag, err)
		}
		s.Resp = true
	default:
		return errors.New("Unknown choice type for NegotiationToken")
	}
	return nil
}
