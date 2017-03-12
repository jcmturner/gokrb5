package client

import (
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/messages"
)

// Perform a TGS exchange to retrieve a ticket to the specified SPN.
// The ticket retrieved is added to the client's cache.
func (cl *Client) TGSExchange(spn string) error {
	if cl.Session == nil {
		return errors.New("Error client does not have a session. Client needs to login first")
	}
	tgs, err := messages.NewTGSReq(cl.Credentials.Username, cl.Config, cl.Session.TGT, cl.Session.SessionKey, "HTTP/host.test.gokrb5")
	if err != nil {
		return fmt.Errorf("Error generating New TGS_REQ: %v", err)
	}
	b, err := tgs.Marshal()
	if err != nil {
		return fmt.Errorf("Error marshalling TGS_REQ: %v", err)
	}
	r, err := cl.SendToKDC(b)
	if err != nil {
		return fmt.Errorf("Error sending TGS_REQ to KDC: %v", err)
	}
	var tgsRep messages.TGSRep
	err = tgsRep.Unmarshal(r)
	if err != nil {
		return fmt.Errorf("Error unmarshalling TGS_REP: %v", err)
	}
	err = tgsRep.DecryptEncPart(cl.Session.SessionKey)
	if err != nil {
		return fmt.Errorf("Error decrypting EncPart of TGS_REP: %v", err)
	}
	if ok, err := tgsRep.IsValid(cl.Config, tgs); !ok {
		return fmt.Errorf("TGS_REP is not valid: %v", err)
	}
	cl.Cache.AddEntry(tgsRep.Ticket, tgsRep.DecryptedEncPart.AuthTime, tgsRep.DecryptedEncPart.EndTime, tgsRep.DecryptedEncPart.RenewTill)
	return nil
}
