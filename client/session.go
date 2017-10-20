package client

import (
	"fmt"
	"gopkg.in/jcmturner/gokrb5.v1/iana/nametype"
	"gopkg.in/jcmturner/gokrb5.v1/krberror"
	"gopkg.in/jcmturner/gokrb5.v1/messages"
	"gopkg.in/jcmturner/gokrb5.v1/types"
	"sync"
	"time"
)

// Sessions keyed on the realm name
type sessions struct {
	Entries map[string]*session
	mux     sync.RWMutex
}

// Client session struct.
type session struct {
	Realm                string
	AuthTime             time.Time
	EndTime              time.Time
	RenewTill            time.Time
	TGT                  messages.Ticket
	SessionKey           types.EncryptionKey
	SessionKeyExpiration time.Time
}

//
func (cl *Client) AddSession(tkt messages.Ticket, dep messages.EncKDCRepPart) {
	cl.sessions.mux.Lock()
	defer cl.sessions.mux.Unlock()
	s := &session{
		Realm:                tkt.SName.NameString[1],
		AuthTime:             dep.AuthTime,
		EndTime:              dep.EndTime,
		RenewTill:            dep.RenewTill,
		TGT:                  tkt,
		SessionKey:           dep.Key,
		SessionKeyExpiration: dep.KeyExpiration,
	}
	cl.sessions.Entries[tkt.SName.NameString[1]] = s
	cl.EnableAutoSessionRenewal(s)
}

// EnableAutoSessionRenewal turns on the automatic renewal for the client's TGT session.
func (cl *Client) EnableAutoSessionRenewal(s *session) {
	// TODO look into using a context here
	go func(s *session) {
		for {
			//Wait until one minute before endtime
			w := (s.EndTime.Sub(time.Now().UTC()) * 5) / 6
			if w < 0 {
				return
			}
			time.Sleep(w)
			cl.updateSession(s)
		}
	}(s)
}

// RenewTGT renews the client's TGT session.
func (cl *Client) RenewTGT(s *session) error {
	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", s.Realm},
	}
	_, tgsRep, err := cl.TGSExchange(spn, s.TGT.Realm, s.TGT, s.SessionKey, true, 0)
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "Error renewing TGT")
	}
	s.AuthTime = tgsRep.DecryptedEncPart.AuthTime
	s.AuthTime = tgsRep.DecryptedEncPart.AuthTime
	s.EndTime = tgsRep.DecryptedEncPart.EndTime
	s.RenewTill = tgsRep.DecryptedEncPart.RenewTill
	s.TGT = tgsRep.Ticket
	s.SessionKey = tgsRep.DecryptedEncPart.Key
	s.SessionKeyExpiration = tgsRep.DecryptedEncPart.KeyExpiration
	return nil
}

func (cl *Client) updateSession(s *session) error {
	if time.Now().UTC().Before(s.RenewTill) {
		err := cl.RenewTGT(s)
		if err != nil {
			return err
		}
	} else {
		err := cl.ASExchange(s.Realm, 0)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cl *Client) GetSessionFromRealm(realm string) (sess *session, err error) {
	var ok bool
	cl.sessions.mux.RLock()
	defer cl.sessions.mux.RUnlock()
	sess, ok = cl.sessions.Entries[realm]
	if !ok {
		sess, ok = cl.sessions.Entries[cl.Config.LibDefaults.DefaultRealm]
		if !ok {
			err = fmt.Errorf("client does not have a session for realm %s or for the default realm %s, login first", realm, cl.Config.LibDefaults.DefaultRealm)
			return
		}
	}
	return
}

func (cl *Client) GetSessionFromPrincipalName(spn types.PrincipalName) (*session, error) {
	realm := cl.Config.ResolveRealm(spn.NameString[1])
	return cl.GetSessionFromRealm(realm)
}
