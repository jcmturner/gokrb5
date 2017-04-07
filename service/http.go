package service

import (
	"net/http"
	"strings"
	"encoding/base64"
	"github.com/jcmturner/gokrb5/GSSAPI"
	"errors"
	"fmt"
)

func SPNEGOHandler(w http.ResponseWriter, r *http.Request, ) {

}

func SPNEGOKRB5Authenticate(w http.ResponseWriter, r *http.Request) (bool, error) {
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

	return true, nil
}
