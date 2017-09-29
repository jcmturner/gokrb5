package client

import (
	"gopkg.in/jcmturner/gokrb5.v1/iana/nametype"
	"gopkg.in/jcmturner/gokrb5.v1/krberror"
	"gopkg.in/jcmturner/gokrb5.v1/messages"
	"gopkg.in/jcmturner/gokrb5.v1/types"
	"time"
)

// Client session struct.
type session struct {
	AuthTime             time.Time
	EndTime              time.Time
	RenewTill            time.Time
	TGT                  messages.Ticket
	SessionKey           types.EncryptionKey
	SessionKeyExpiration time.Time
}

// EnableAutoSessionRenewal turns on the automatic renewal for the client's TGT session.
func (cl *Client) EnableAutoSessionRenewal() {
	// TODO look into using a context here
	go func() {
		for {
			//Wait until one minute before endtime
			w := (cl.session.EndTime.Sub(time.Now().UTC()) * 5) / 6
			if w < 0 {
				return
			}
			time.Sleep(w)
			cl.updateTGT()
		}
	}()
}

// RenewTGT renews the client's TGT session.
func (cl *Client) RenewTGT() error {
	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", cl.session.TGT.Realm},
	}
	_, tgsRep, err := cl.TGSExchange(spn, cl.session.TGT, cl.session.SessionKey, true)
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "Error renewing TGT")
	}
	cl.session = &session{
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
	if time.Now().UTC().Before(cl.session.RenewTill) {
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
