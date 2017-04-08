package service

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/GSSAPI"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/iana/errorcode"
	"github.com/jcmturner/gokrb5/iana/keyusage"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/types"
	"net/http"
	"strings"
	"time"
)

// Authenticate the request. Returns:
//
// boolean: indicates if authenticate succeeded
//
// string: client principal name
//
// string: client realm
//
// error: reason for any authentication failure
func SPNEGOKRB5Authenticate(w http.ResponseWriter, r *http.Request, ktab keytab.Keytab) (bool, string, string, error) {
	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 || s[0] != "Negotiate" {
		// TODO set the NegTokenResp Negotiate header here on the w
		return false, nil, nil, errors.New("No Authorization header with Negotiate content found")
	}
	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return false, nil, nil, fmt.Errorf("Authorization header Negotiate content could not be base64 decoded: %v", err)
	}
	isInit, nt, err := GSSAPI.UnmarshalNegToken(b)
	if err != nil || !isInit {
		return false, nil, nil, fmt.Errorf("SPNEGO negotiation token is not a NegTokenInit: %v", err)
	}
	nInit := nt.(GSSAPI.NegTokenInit)
	if nInit.MechTypes != GSSAPI.MechTypeOID_Krb5 {
		return false, nil, nil, errors.New("OID of MechToken is not of type KRB5")
	}
	var mt GSSAPI.MechToken
	err = mt.Unmarshal(nInit.MechToken)
	if err != nil {
		return false, nil, nil, fmt.Errorf("Error unmarshalling MechToken: %v", err)
	}
	if !mt.IsAPReq() {
		return false, nil, nil, errors.New("MechToken does not contain an AP_REQ - KRB_AP_ERR_MSG_TYPE")
	}
	err = mt.APReq.Ticket.DecryptEncPart(ktab)
	if err != nil {
		return false, nil, nil, fmt.Errorf("Error decrypting the service ticket provided: %v", err)
	}
	ab, err := crypto.DecryptEncPart(mt.APReq.Authenticator, mt.APReq.Ticket.DecryptedEncPart.Key, keyusage.AP_REQ_AUTHENTICATOR)
	if err != nil {
		return false, nil, nil, fmt.Errorf("Error decrypting the authenticator provided: %v", err)
	}
	var a types.Authenticator
	err = a.Unmarshal(ab)
	if err != nil {
		return false, nil, nil, fmt.Errorf("Error unmarshalling the authenticator: %v", err)
	}
	// VALIDATIONS
	// Check CName in Authenticator is the same as that in the ticket
	if !a.CName.Equal(mt.APReq.Ticket.DecryptedEncPart.CName) {
		return false, nil, nil, messages.NewKRBError(mt.APReq.Ticket.SName, mt.APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADMATCH, "CName in Authenticator does not match that in service ticket")
	}
	// TODO client address check
	//The addresses in the ticket (if any) are then
	//searched for an address matching the operating-system reported
	//address of the client.  If no match is found or the server insists on
	//ticket addresses but none are present in the ticket, the
	//KRB_AP_ERR_BADADDR error is returned.

	// Check the clock skew between the client and the service server
	ct := a.CTime.Add(time.Duration(a.Cusec) * time.Microsecond)
	t := time.Now().UTC()
	// Hardcode 5 min max skew. May want to make this configurable
	d := time.Duration(5) * time.Minute
	if t.Sub(ct) > d || ct.Sub(t) > d {
		return false, nil, nil, messages.NewKRBError(mt.APReq.Ticket.SName, mt.APReq.Ticket.Realm, errorcode.KRB_AP_ERR_SKEW, fmt.Sprintf("Clock skew with client too large. Greater than %v seconds", d))
	}

	// Check for replay
	rc := GetReplayCache(d)
	if rc.IsReplay(d, mt.APReq.Ticket.SName, a) {
		return false, nil, nil, messages.NewKRBError(mt.APReq.Ticket.SName, mt.APReq.Ticket.Realm, errorcode.KRB_AP_ERR_REPEAT, "Replay detected")
	}

	// Check for future tickets or invalid tickets
	if mt.APReq.Ticket.DecryptedEncPart.StartTime.Sub(t) > d || types.IsFlagSet(mt.APReq.Ticket.DecryptedEncPart.Flags, types.Invalid) {
		return false, nil, nil, messages.NewKRBError(mt.APReq.Ticket.SName, mt.APReq.Ticket.Realm, errorcode.KRB_AP_ERR_TKT_NYV, "Service ticket provided is not yet valid")
	}

	// Check for expired ticket
	if t.Sub(mt.APReq.Ticket.DecryptedEncPart.EndTime) > d {
		return false, nil, nil, messages.NewKRBError(mt.APReq.Ticket.SName, mt.APReq.Ticket.Realm, errorcode.KRB_AP_ERR_TKT_EXPIRED, "Service ticket provided has expired")
	}
	return true, a.CName.GetPrincipalNameString(), a.CRealm, nil
}
