package client

import (
	"fmt"
	"sync"
	"time"

	"gopkg.in/jcmturner/gokrb5.v6/iana/nametype"
	"gopkg.in/jcmturner/gokrb5.v6/krberror"
	"gopkg.in/jcmturner/gokrb5.v6/messages"
	"gopkg.in/jcmturner/gokrb5.v6/types"
)

// Sessions keyed on the realm name
type sessions struct {
	Entries map[string]*session
	mux     sync.RWMutex
}

func (s *sessions) destroy() {
	s.mux.Lock()
	defer s.mux.Unlock()
	for k, e := range s.Entries {
		e.destroy()
		delete(s.Entries, k)
	}
}

// Client session struct.
type session struct {
	realm                string
	authTime             time.Time
	endTime              time.Time
	renewTill            time.Time
	tgt                  messages.Ticket
	sessionKey           types.EncryptionKey
	sessionKeyExpiration time.Time
	cancel               chan bool
	mux                  sync.RWMutex
}

func (s *session) update(tgt messages.Ticket, dep messages.EncKDCRepPart) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.authTime = dep.AuthTime
	s.endTime = dep.EndTime
	s.renewTill = dep.RenewTill
	s.tgt = tgt
	s.sessionKey = dep.Key
	s.sessionKeyExpiration = dep.KeyExpiration
}

func (s *session) destroy() {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.cancel <- true
	s.endTime = time.Now().UTC()
	s.renewTill = s.endTime
	s.sessionKeyExpiration = s.endTime
}

// AddSession adds a session for a realm with a TGT to the client's session cache.
// A goroutine is started to automatically renew the TGT before expiry.
func (cl *Client) AddSession(tgt messages.Ticket, dep messages.EncKDCRepPart) {
	cl.sessions.mux.Lock()
	defer cl.sessions.mux.Unlock()
	s := &session{
		realm:                tgt.SName.NameString[1],
		authTime:             dep.AuthTime,
		endTime:              dep.EndTime,
		renewTill:            dep.RenewTill,
		tgt:                  tgt,
		sessionKey:           dep.Key,
		sessionKeyExpiration: dep.KeyExpiration,
		cancel:               make(chan bool, 1),
	}
	// if a session already exists for this, cancel its auto renew.
	if i, ok := cl.sessions.Entries[tgt.SName.NameString[1]]; ok {
		i.cancel <- true
	}
	cl.sessions.Entries[tgt.SName.NameString[1]] = s
	cl.enableAutoSessionRenewal(s)
}

// enableAutoSessionRenewal turns on the automatic renewal for the client's TGT session.
func (cl *Client) enableAutoSessionRenewal(s *session) {
	var timer *time.Timer
	go func(s *session) {
		for {
			s.mux.RLock()
			w := (s.endTime.Sub(time.Now().UTC()) * 5) / 6
			s.mux.RUnlock()
			if w < 0 {
				return
			}
			timer = time.NewTimer(w)
			select {
			case <-timer.C:
				renewal, err := cl.updateSession(s)
				if !renewal && err == nil {
					// end this goroutine as there will have been a new login and new auto renewal goroutine created.
					return
				}
			case <-s.cancel:
				// cancel has been called. Stop the timer and exit.
				timer.Stop()
				return
			}
		}
	}(s)
}

// RenewTGT renews the client's TGT session.
func (cl *Client) renewTGT(s *session) error {
	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", s.realm},
	}
	_, tgsRep, err := cl.TGSExchange(spn, s.tgt.Realm, s.tgt, s.sessionKey, true, 0)
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "error renewing TGT")
	}
	s.update(tgsRep.Ticket, tgsRep.DecryptedEncPart)
	return nil
}

// updateSession updates either through renewal or creating a new login.
// The boolean indicates if the update was a renewal.
func (cl *Client) updateSession(s *session) (bool, error) {
	if time.Now().UTC().Before(s.renewTill) {
		err := cl.renewTGT(s)
		return true, err
	}
	err := cl.Login()
	return false, err
}

func (cl *Client) sessionFromRemoteRealm(realm string) (*session, error) {
	cl.sessions.mux.RLock()
	sess, ok := cl.sessions.Entries[cl.Credentials.Realm]
	cl.sessions.mux.RUnlock()
	if !ok {
		return nil, fmt.Errorf("client does not have a session for realm %s, login first", cl.Credentials.Realm)
	}

	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}

	_, tgsRep, err := cl.TGSExchange(spn, cl.Credentials.Realm, sess.tgt, sess.sessionKey, false, 0)
	if err != nil {
		return nil, err
	}
	cl.AddSession(tgsRep.Ticket, tgsRep.DecryptedEncPart)

	cl.sessions.mux.RLock()
	defer cl.sessions.mux.RUnlock()
	return cl.sessions.Entries[realm], nil
}

// GetSessionFromRealm returns the session for the realm provided.
func (cl *Client) sessionFromRealm(realm string) (sess *session, err error) {
	cl.sessions.mux.RLock()
	s, ok := cl.sessions.Entries[realm]
	cl.sessions.mux.RUnlock()
	if !ok {
		// Try to request TGT from trusted remote Realm
		s, err = cl.sessionFromRemoteRealm(realm)
		if err != nil {
			return
		}
	}
	// Create another session to return to prevent race condition.
	sess = &session{
		realm:                s.realm,
		authTime:             s.authTime,
		endTime:              s.endTime,
		renewTill:            s.renewTill,
		tgt:                  s.tgt,
		sessionKey:           s.sessionKey,
		sessionKeyExpiration: s.sessionKeyExpiration,
	}
	return
}

// GetSessionFromPrincipalName returns the session for the realm of the principal provided.
func (cl *Client) sessionFromPrincipalName(spn types.PrincipalName) (*session, error) {
	realm := cl.Config.ResolveRealm(spn.NameString[len(spn.NameString)-1])
	return cl.sessionFromRealm(realm)
}
