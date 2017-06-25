package client

import (
	"errors"
	"github.com/jcmturner/gokrb5/iana/nametype"
	"github.com/jcmturner/gokrb5/krberror"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/types"
	"strings"
	"time"
)

// TGSExchange performs a TGS exchange to retrieve a ticket to the specified SPN.
// The ticket retrieved is added to the client's cache.
func (cl *Client) TGSExchange(spn types.PrincipalName, tkt messages.Ticket, sessionKey types.EncryptionKey, renewal bool) (tgsReq messages.TGSReq, tgsRep messages.TGSRep, err error) {
	if cl.session == nil {
		return tgsReq, tgsRep, errors.New("TGS Exchange Error: client does not have a session. Client needs to login first")
	}
	tgsReq, err = messages.NewTGSReq(cl.Credentials.CName, cl.Config, tkt, sessionKey, spn, renewal)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.KRBMSG_ERROR, "TGS Exchange Error: failed to generate a new TGS_REQ")
	}
	b, err := tgsReq.Marshal()
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.ENCODING_ERROR, "TGS Exchange Error: failed to generate a new TGS_REQ")
	}
	r, err := cl.SendToKDC(b)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.NETWORKING_ERROR, "TGS Exchange Error: issue sending TGS_REQ to KDC")
	}
	err = tgsRep.Unmarshal(r)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.ENCODING_ERROR, "TGS Exchange Error: failed to process the TGS_REP")
	}
	err = tgsRep.DecryptEncPart(sessionKey)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.ENCODING_ERROR, "TGS Exchange Error: failed to process the TGS_REP")
	}
	if ok, err := tgsRep.IsValid(cl.Config, tgsReq); !ok {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.ENCODING_ERROR, "TGS Exchange Error: TGS_REP is not valid")
	}
	return tgsReq, tgsRep, nil
}

// GetServiceTicket makes a request to get a service ticket for the SPN specified
// SPN format: <SERVICE>/<FQDN> Eg. HTTP/www.example.com
// The ticket will be added to the client's ticket cache
func (cl *Client) GetServiceTicket(spn string) (messages.Ticket, types.EncryptionKey, error) {
	var tkt messages.Ticket
	var skey types.EncryptionKey
	if tkt, skey, ok := cl.GetCachedTicket(spn); ok {
		// Already a valid ticket in the cache
		return tkt, skey, nil
	}
	// Ensure TGT still valid
	if time.Now().UTC().After(cl.session.EndTime) {
		err := cl.updateTGT()
		if err != nil {
			return tkt, skey, err
		}
	}
	s := strings.Split(spn, "/")
	princ := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: s,
	}
	_, tgsRep, err := cl.TGSExchange(princ, cl.session.TGT, cl.session.SessionKey, false)
	if err != nil {
		return tkt, skey, err
	}
	cl.Cache.addEntry(
		tgsRep.Ticket,
		tgsRep.DecryptedEncPart.AuthTime,
		tgsRep.DecryptedEncPart.StartTime,
		tgsRep.DecryptedEncPart.EndTime,
		tgsRep.DecryptedEncPart.RenewTill,
		tgsRep.DecryptedEncPart.Key,
	)
	return tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, nil
}
