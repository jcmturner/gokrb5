package client

import (
	"fmt"
	"github.com/jcmturner/gokrb5/iana/nametype"
	"github.com/jcmturner/gokrb5/types"
	"os"
	"time"
)

// Client session struct.
type Session struct {
	AuthTime             time.Time
	EndTime              time.Time
	RenewTill            time.Time
	TGT                  types.Ticket
	SessionKey           types.EncryptionKey
	SessionKeyExpiration time.Time
}

func (cl *Client) RenewTGT() error {
	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", cl.Session.TGT.Realm},
	}
	_, tgsRep, err := cl.TGSExchange(spn, true)
	if err != nil {
		return err
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

func (cl *Client) EnableAutoSessionRenewal() {
	go func() {
		for {
			//Wait until one minute before endtime
			w := (time.Until(cl.Session.EndTime) * 5) / 6
			if w < 0 {
				return
			}
			time.Sleep(w)
			if time.Now().Before(cl.Session.RenewTill) {
				cl.RenewTGT()
			} else {
				cl.Login()
			}
		}
	}()
}
