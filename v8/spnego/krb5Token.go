package spnego

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/types"
)

// GSSAPI KRB5 MechToken IDs.
const (
	TOK_ID_KRB_AP_REQ = "0100"
	TOK_ID_KRB_AP_REP = "0200"
	TOK_ID_KRB_ERROR  = "0300"
)

// KRB5Token context token implementation for GSSAPI.
type KRB5Token struct {
	OID      asn1.ObjectIdentifier
	tokID    []byte
	APReq    messages.APReq
	APRep    messages.APRep
	KRBError messages.KRBError
	settings *service.Settings
	context  context.Context
}

// Marshal a KRB5Token into a slice of bytes.
func (m *KRB5Token) Marshal() ([]byte, error) {
	// Create the header
	b, _ := asn1.Marshal(m.OID)
	b = append(b, m.tokID...)
	var tb []byte
	var err error
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		tb, err = m.APReq.Marshal()
		if err != nil {
			return []byte{}, fmt.Errorf("error marshalling AP_REQ for MechToken: %v", err)
		}
	case TOK_ID_KRB_AP_REP:
		return []byte{}, errors.New("marshal of AP_REP GSSAPI MechToken not supported by gokrb5")
	case TOK_ID_KRB_ERROR:
		return []byte{}, errors.New("marshal of KRB_ERROR GSSAPI MechToken not supported by gokrb5")
	}
	if err != nil {
		return []byte{}, fmt.Errorf("error mashalling kerberos message within mech token: %v", err)
	}
	b = append(b, tb...)
	return asn1tools.AddASNAppTag(b, 0), nil
}

// Unmarshal a KRB5Token.
func (m *KRB5Token) Unmarshal(b []byte) error {
	var oid asn1.ObjectIdentifier
	r, err := asn1.UnmarshalWithParams(b, &oid, fmt.Sprintf("application,explicit,tag:%v", 0))
	if err != nil {
		return fmt.Errorf("error unmarshalling KRB5Token OID: %v", err)
	}
	if !oid.Equal(gssapi.OIDKRB5.OID()) {
		return fmt.Errorf("error unmarshalling KRB5Token, OID is %s not %s", oid.String(), gssapi.OIDKRB5.OID().String())
	}
	m.OID = oid
	if len(r) < 2 {
		return fmt.Errorf("krb5token too short")
	}
	m.tokID = r[0:2]
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		var a messages.APReq
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token AP_REQ: %v", err)
		}
		m.APReq = a
	case TOK_ID_KRB_AP_REP:
		var a messages.APRep
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token AP_REP: %v", err)
		}
		m.APRep = a
	case TOK_ID_KRB_ERROR:
		var a messages.KRBError
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token KRBError: %v", err)
		}
		m.KRBError = a
	}
	return nil
}

// Verify a KRB5Token.
func (m *KRB5Token) Verify() (bool, gssapi.Status) {
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		ok, creds, err := service.VerifyAPREQ(&m.APReq, m.settings)
		if err != nil {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
		}
		if !ok {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveCredential, Message: "KRB5_AP_REQ token not valid"}
		}
		m.context = context.Background()
		m.context = context.WithValue(m.context, ctxCredentials, creds)
		return true, gssapi.Status{Code: gssapi.StatusComplete}
	case TOK_ID_KRB_AP_REP:
		// Client side
		// TODO how to verify the AP_REP - not yet implemented
		return false, gssapi.Status{Code: gssapi.StatusFailure, Message: "verifying an AP_REP is not currently supported by gokrb5"}
	case TOK_ID_KRB_ERROR:
		if m.KRBError.MsgType != msgtype.KRB_ERROR {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "KRB5_Error token not valid"}
		}
		return true, gssapi.Status{Code: gssapi.StatusUnavailable}
	}
	return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "unknown TOK_ID in KRB5 token"}
}

// IsAPReq tests if the MechToken contains an AP_REQ.
func (m *KRB5Token) IsAPReq() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_AP_REQ {
		return true
	}
	return false
}

// IsAPRep tests if the MechToken contains an AP_REP.
func (m *KRB5Token) IsAPRep() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_AP_REP {
		return true
	}
	return false
}

// IsKRBError tests if the MechToken contains an KRB_ERROR.
func (m *KRB5Token) IsKRBError() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_ERROR {
		return true
	}
	return false
}

// Context returns the KRB5 token's context which will contain any verify user identity information.
func (m *KRB5Token) Context() context.Context {
	return m.context
}

// NewKRB5TokenAPREQ creates a new KRB5 token with AP_REQ.
// For backward compatibility, use nil for bindings if channel bindings are not needed.
func NewKRB5TokenAPREQ(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, GSSAPIFlags []int, APOptions []int) (KRB5Token, error) {
	return NewKRB5TokenAPREQWithBindings(cl, tkt, sessionKey, GSSAPIFlags, APOptions, nil)
}

// NewKRB5TokenAPREQWithBindings creates a new KRB5 token with AP_REQ and optional channel bindings.
// The bindings parameter can be nil if channel bindings are not required.
// When bindings is non-nil, the MD5 hash of the serialized bindings is embedded in the
// authenticator checksum per RFC 4121 Section 4.1.1.
func NewKRB5TokenAPREQWithBindings(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, GSSAPIFlags []int, APOptions []int, bindings *gssapi.ChannelBindings) (KRB5Token, error) {
	// TODO consider providing the SPN rather than the specific tkt and key and get these from the krb client.
	var m KRB5Token
	m.OID = gssapi.OIDKRB5.OID()
	tb, _ := hex.DecodeString(TOK_ID_KRB_AP_REQ)
	m.tokID = tb

	auth, err := krb5TokenAuthenticator(cl.Credentials, GSSAPIFlags, bindings)
	if err != nil {
		return m, err
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		auth,
	)
	if err != nil {
		return m, err
	}
	for _, o := range APOptions {
		types.SetFlag(&APReq.APOptions, o)
	}
	m.APReq = APReq
	return m, nil
}

// krb5TokenAuthenticator creates a new kerberos authenticator for kerberos MechToken.
// The bindings parameter can be nil if channel bindings are not required.
func krb5TokenAuthenticator(creds *credentials.Credentials, flags []int, bindings *gssapi.ChannelBindings) (types.Authenticator, error) {
	//RFC 4121 Section 4.1.1
	auth, err := types.NewAuthenticator(creds.Domain(), creds.CName())
	if err != nil {
		return auth, krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")
	}
	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  newAuthenticatorChksum(flags, bindings),
	}
	return auth, nil
}

// newAuthenticatorChksum creates the authenticator checksum for kerberos MechToken.
// Per RFC 4121 Section 4.1.1, the checksum format is:
//   - Bytes 0-3:   Lgth (length of Bnd field, always 16)
//   - Bytes 4-19:  Bnd (MD5 hash of channel bindings, or zeros if no bindings)
//   - Bytes 20-23: Flags (context establishment flags)
//   - Bytes 24+:   Optional delegation data
//
// When bindings is non-nil, the MD5 hash of the serialized channel bindings
// is placed in the Bnd field (bytes 4-19). When bindings is nil, the Bnd field
// contains zeros (current behavior for backward compatibility).
func newAuthenticatorChksum(flags []int, bindings *gssapi.ChannelBindings) []byte {
	a := make([]byte, 24)

	// Lgth field - always 16 (the size of MD5 hash)
	binary.LittleEndian.PutUint32(a[:4], 16)

	// Bnd field - MD5 hash of channel bindings or zeros
	if bindings != nil {
		hash := bindings.MD5Hash()
		copy(a[4:20], hash[:])
	}
	// else: bytes 4-19 remain as zeros (no channel bindings)

	// Process flags
	for _, i := range flags {
		if i == gssapi.ContextFlagDeleg {
			x := make([]byte, 28-len(a))
			a = append(a, x...)
		}
		f := binary.LittleEndian.Uint32(a[20:24])
		f |= uint32(i)
		binary.LittleEndian.PutUint32(a[20:24], f)
	}

	return a
}
