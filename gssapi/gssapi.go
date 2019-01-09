// Package gssapi implements Generic Security Services Application Program Interface required for SPNEGO kerberos authentication.
package gssapi

import (
	"context"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
)

const (
	OIDKRB5         OIDName = "KRB5"         // MechType OID for Kerberos 5
	OIDMSLegacyKRB5 OIDName = "MSLegacyKRB5" // MechType OID for Kerberos 5
	OIDSPNEGO       OIDName = "SPNEGO"

	// GSS-API status values
	StatusBadBindings = 1 << iota
	StatusBadMech
	StatusBadName
	StatusBadNameType
	StatusBadStatus
	StatusBadSig
	StatusBadMIC
	StatusContextExpired
	StatusCredentialsExpired
	StatusDefectiveCredential
	StatusDefectiveToken
	StatusFailure
	StatusNoContext
	StatusNoCred
	StatusBadQOP
	StatusUnauthorized
	StatusUnavailable
	StatusDuplicateElement
	StatusNameNotMN
	StatusComplete
	StatusContinueNeeded
	StatusDuplicateToken
	StatusOldToken
	StatusUnseqToken
	StatusGapToken
)

type ContextToken interface {
	Marshal() ([]byte, error)
	Unmarshal(b []byte) error
	Verify() (bool, Status)
	Context() context.Context
}

type Mechanism interface {
	OID() asn1.ObjectIdentifier
	AcquireCred() error                                              //ASExchange - Client Side
	InitSecContext() (ContextToken, error)                           //TGSExchnage builds AP_REQ to go into ContextToken to send to service - Client Side
	AcceptSecContext(ct ContextToken) (bool, context.Context, error) //verifies the AP_REQ
	MIC() MICToken                                                   //  apply integrity check, receive as token separate from message
	VerifyMIC(mt MICToken)                                           //validate integrity check token along with message
	Wrap(msg []byte) WrapToken                                       //  sign, optionally encrypt, encapsulate
	Unwrap(wt WrapToken) []byte                                      //decapsulate, decrypt if needed, validate integrity check
}

type OIDName string

func OID(o OIDName) asn1.ObjectIdentifier {
	switch o {
	case OIDSPNEGO:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}
	case OIDKRB5:
		return asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
	case OIDMSLegacyKRB5:
		return asn1.ObjectIdentifier{1, 2, 840, 48018, 1, 2, 2}
	}
	return asn1.ObjectIdentifier{}
}

type Status struct {
	Code    int
	Message string
}

func (s Status) Error() string {
	var str string
	switch s.Code {
	case StatusBadBindings:
		str = "channel binding mismatch"
	case StatusBadMech:
		str = "unsupported mechanism requested"
	case StatusBadName:
		str = "invalid name provided"
	case StatusBadNameType:
		str = "name of unsupported type provided"
	case StatusBadStatus:
		str = "invalid input status selector"
	case StatusBadSig:
		str = "token had invalid integrity check"
	case StatusBadMIC:
		str = "preferred alias for GSS_S_BAD_SIG"
	case StatusContextExpired:
		str = "specified security context expired"
	case StatusCredentialsExpired:
		str = "expired credentials detected"
	case StatusDefectiveCredential:
		str = "defective credential detected"
	case StatusDefectiveToken:
		str = "defective token detected"
	case StatusFailure:
		str = "failure, unspecified at GSS-API level"
	case StatusNoContext:
		str = "no valid security context specified"
	case StatusNoCred:
		str = "no valid credentials provided"
	case StatusBadQOP:
		str = "unsupported QOP valu"
	case StatusUnauthorized:
		str = "operation unauthorized"
	case StatusUnavailable:
		str = "operation unavailable"
	case StatusDuplicateElement:
		str = "duplicate credential element requested"
	case StatusNameNotMN:
		str = "name contains multi-mechanism elements"
	case StatusComplete:
		str = "normal completion"
	case StatusContinueNeeded:
		str = "continuation call to routine required"
	case StatusDuplicateToken:
		str = "duplicate per-message token detected"
	case StatusOldToken:
		str = "timed-out per-message token detected"
	case StatusUnseqToken:
		str = "reordered (early) per-message token detected"
	case StatusGapToken:
		str = "skipped predecessor token(s) detected"
	default:
		str = "unknown GSS-API error status"
	}
	if s.Message != "" {
		return fmt.Sprintf("%s: %s", str, s.Message)
	}
	return str
}
