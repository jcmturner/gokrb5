package client

import (
	"encoding/base64"
	"fmt"
	"github.com/jcmturner/gokrb5/GSSAPI"
	"net/http"
	"strings"
)

// Get service ticket and set as the SPNEGO authorization header on HTTP request object.
// To auto generate the SPN from the request object pass a null string "".
func (cl *Client) SetSPNEGOHeader(HTTPReq *http.Request, spn string) error {
	if spn == "" {
		spn = "HTTP/" + strings.SplitN(HTTPReq.Host, ":", 2)[0]
	}
	tkt, skey, err := cl.GetServiceTicket(spn)
	if err != nil {
		return fmt.Errorf("Could not get service ticket: %v", err)
	}
	negTokenInit, err := GSSAPI.NewNegTokenInitKrb5(*cl.Config, cl.Credentials.CName, tkt, skey)
	if err != nil {
		return fmt.Errorf("Could not create NegTokenInit: %v", err)
	}
	SPNEGOToken := GSSAPI.SPNEGO{
		Init:         true,
		NegTokenInit: negTokenInit,
	}
	nb, err := SPNEGOToken.Marshal()
	if err != nil {
		return fmt.Errorf("Could marshal SPNEGO: %v", err)
	}

	hs := "Negotiate " + base64.StdEncoding.EncodeToString(nb)
	HTTPReq.Header.Set("Authorization", hs)
	return nil
}
