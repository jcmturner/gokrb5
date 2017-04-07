package service

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/GSSAPI"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/iana/keyusage"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/types"
	"net/http"
	"strings"
)

func SPNEGOHandler(w http.ResponseWriter, r *http.Request) {

}

func SPNEGOKRB5Authenticate(w http.ResponseWriter, r *http.Request, ktab keytab.Keytab) (bool, error) {
	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 || s[0] != "Negotiate" {
		// TODO set the NegTokenResp Negotiate header here on the w
		return false, errors.New("No Authorization header with Negotiate content found")
	}
	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return false, fmt.Errorf("Authorization header Negotiate content could not be base64 decoded: %v", err)
	}
	isInit, nt, err := GSSAPI.UnmarshalNegToken(b)
	if err != nil || !isInit {
		return false, fmt.Errorf("SPNEGO negotiation token is not a NegTokenInit: %v", err)
	}
	nInit := nt.(GSSAPI.NegTokenInit)
	if nInit.MechTypes != GSSAPI.MechTypeOID_Krb5 {
		return false, errors.New("OID of MechToken is not of type KRB5")
	}
	var mt GSSAPI.MechToken
	err = mt.Unmarshal(nInit.MechToken)
	if err != nil {
		return false, fmt.Errorf("Error unmarshalling MechToken: %v", err)
	}
	if !mt.IsAPReq() {
		return false, errors.New("MechToken does not contain an AP_REQ")
	}
	err = mt.APReq.Ticket.DecryptEncPart(ktab)
	if err != nil {
		return false, fmt.Errorf("Error decrypting the service ticket provided: %v", err)
	}
	sessionKey := mt.APReq.Ticket.DecryptedEncPart.Key
	ab, err := crypto.DecryptEncPart(mt.APReq.Authenticator, sessionKey, keyusage.AP_REQ_AUTHENTICATOR)
	if err != nil {
		return false, fmt.Errorf("Error decrypting the authenticator provided: %v", err)
	}
	var a types.Authenticator
	err = a.Unmarshal(ab)
	if err != nil {
		return false, fmt.Errorf("Error unmarshalling the authenticator: %v", err)
	}
	// TODO check timestamp within skew etc...

	return true, nil
}
