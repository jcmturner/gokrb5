package client

import (
	"encoding/base64"
	"fmt"
	"github.com/jcmturner/gokrb5/credentials"
	"github.com/jcmturner/gokrb5/gssapi"
	"github.com/jcmturner/gokrb5/krberror"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/types"
	"net/http"
	"strings"
)

// SetSPNEGOHeader gets the service ticket and sets it as the SPNEGO authorization header on HTTP request object.
// To auto generate the SPN from the request object pass a null string "".
func (cl *Client) SetSPNEGOHeader(r *http.Request, spn string) error {
	if spn == "" {
		spn = "HTTP/" + strings.SplitN(r.Host, ":", 2)[0]
	}
	tkt, skey, err := cl.GetServiceTicket(spn)
	if err != nil {
		return fmt.Errorf("Could not get service ticket: %v", err)
	}
	err = SetSPNEGOHeader(*cl.Credentials, tkt, skey, r)
	if err != nil {
		return err
	}
	return nil
}

// SetSPNEGOHeader sets the provided ticket as the SPNEGO authorization header on HTTP request object.
func SetSPNEGOHeader(creds credentials.Credentials, tkt messages.Ticket, sessionKey types.EncryptionKey, r *http.Request) error {
	SPNEGOToken, err := gssapi.GetSPNEGOKrbNegTokenInit(creds, tkt, sessionKey)
	nb, err := SPNEGOToken.Marshal()
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "Could marshal SPNEGO")
	}
	hs := "Negotiate " + base64.StdEncoding.EncodeToString(nb)
	r.Header.Set("Authorization", hs)
	return nil
}
