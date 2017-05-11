package client

import (
	"github.com/jcmturner/gokrb5/iana/nametype"
	"github.com/jcmturner/gokrb5/krberror"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/types"
	"time"
)

// Client session struct.
type Session struct {
	AuthTime             time.Time
	EndTime              time.Time
	RenewTill            time.Time
	TGT                  messages.Ticket
	SessionKey           types.EncryptionKey
	SessionKeyExpiration time.Time
}

//Enable the automatic renewal for the client's TGT session.
func (cl *Client) EnableAutoSessionRenewal() {
	// TODO look into using a context here
	go func() {
		for {
			//Wait until one minute before endtime
			w := (cl.Session.EndTime.Sub(time.Now().UTC()) * 5) / 6
			if w < 0 {
				return
			}
			time.Sleep(w)
			cl.updateTGT()
		}
	}()
}

//Renew the client's TGT session.
func (cl *Client) RenewTGT() error {
	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", cl.Session.TGT.Realm},
	}
	_, tgsRep, err := cl.TGSExchange(spn, cl.Session.TGT, cl.Session.SessionKey, true)
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMSG_ERROR, "Error renewing TGT")
	}
	cl.Session = &Session{
		AuthTime:             tgsRep.DecryptedEncPart.AuthTime,
		EndTime:              tgsRep.DecryptedEncPart.EndTime,
		RenewTill:            tgsRep.DecryptedEncPart.RenewTill,
		TGT:                  tgsRep.Ticket,
		SessionKey:           tgsRep.DecryptedEncPart.Key,
		SessionKeyExpiration: tgsRep.DecryptedEncPart.KeyExpiration,
	}
	return nil
}

func (cl *Client) updateTGT() error {
	if time.Now().UTC().Before(cl.Session.RenewTill) {
		err := cl.RenewTGT()
		if err != nil {
			return err
		}
	} else {
		err := cl.Login()
		if err != nil {
			return err
		}
	}
	return nil
}
