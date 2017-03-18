package client

import (
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/iana/nametype"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/types"
	"os"
	"strings"
	"time"
)

// Perform a TGS exchange to retrieve a ticket to the specified SPN.
// The ticket retrieved is added to the client's cache.
func (cl *Client) TGSExchange(spn types.PrincipalName, tkt types.Ticket, sessionKey types.EncryptionKey, renewal bool) (tgsReq messages.TGSReq, tgsRep messages.TGSRep, err error) {
	if cl.Session == nil {
		return tgsReq, tgsRep, errors.New("Error client does not have a session. Client needs to login first")
	}
	tgsReq, err = messages.NewTGSReq(cl.Credentials.Username, cl.Config, tkt, sessionKey, spn, renewal)
	if err != nil {
		return tgsReq, tgsRep, fmt.Errorf("Error generating New TGS_REQ: %v", err)
	}
	b, err := tgsReq.Marshal()
	if err != nil {
		return tgsReq, tgsRep, fmt.Errorf("Error marshalling TGS_REQ: %v", err)
	}
	r, err := cl.SendToKDC(b)
	if err != nil {
		return tgsReq, tgsRep, fmt.Errorf("Error sending TGS_REQ to KDC: %v", err)
	}
	err = tgsRep.Unmarshal(r)
	if err != nil {
		return tgsReq, tgsRep, fmt.Errorf("Error unmarshalling TGS_REP: %v", err)
	}
	err = tgsRep.DecryptEncPart(sessionKey)
	if err != nil {
		return tgsReq, tgsRep, fmt.Errorf("Error decrypting EncPart of TGS_REP: %v", err)
	}
	fmt.Fprintf(os.Stderr, "TGSRep: %+v\n", tgsRep)
	if ok, err := tgsRep.IsValid(cl.Config, tgsReq); !ok {
		return tgsReq, tgsRep, fmt.Errorf("TGS_REP is not valid: %v", err)
	}
	return tgsReq, tgsRep, nil
}

// Make a request to get a service ticket for the SPN specified
// SPN format: <SERVICE>/<FQDN> Eg. HTTP/www.example.com
// The ticket will be added to the client's ticket cache
func (cl *Client) GetServiceTicket(spn string) error {
	if _, ok := cl.GetCachedTicket(spn); ok {
		// Already a valid ticket in the cache
		return nil
	}
	// Ensure TGT still valid
	if time.Now().After(cl.Session.EndTime) {
		err := cl.updateTGT()
		if err != nil {
			return err
		}
	}
	s := strings.Split(spn, "/")
	princ := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: s,
	}
	_, tgsRep, err := cl.TGSExchange(princ, cl.Session.TGT, cl.Session.SessionKey, false)
	if err != nil {
		return err
	}
	cl.Cache.AddEntry(
		tgsRep.Ticket,
		tgsRep.DecryptedEncPart.AuthTime,
		tgsRep.DecryptedEncPart.EndTime,
		tgsRep.DecryptedEncPart.RenewTill,
		tgsRep.DecryptedEncPart.Key,
	)
	e, _ := cl.Cache.GetEntry(spn)
	fmt.Fprintf(os.Stderr, "ServiceTkt: %+v", e)
	return nil
}
