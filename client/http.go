package client

import (
	"github.com/jcmturner/gokrb5/GSSAPI"
	"fmt"
	"net/http"
	"encoding/base64"
)

func (cl *Client) SetKRB5NegotiationHeader(HTTPReq *http.Request, spn string) error {
	tkt, skey, err := cl.GetServiceTicket(spn)
	if err != nil {
		return fmt.Errorf("Could not get service ticket: %v", err)
	}
	negTokenInit, err := GSSAPI.NewNegTokenInitKrb5(*cl.Config, cl.Credentials.CName, tkt, skey)
	if err != nil {
		return fmt.Errorf("Could not create NegTokenInit: %v", err)
	}
	nb, err := negTokenInit.Marshal()
	if err != nil {
		return fmt.Errorf("Could marshal NegTokenInit: %v", err)
	}

	hs := "Negotiate " + base64.StdEncoding.EncodeToString(nb)
	HTTPReq.Header.Set("Authorization", hs)
	return nil
}