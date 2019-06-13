// +build examples

package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"gopkg.in/jcmturner/goidentity.v4"
	"gopkg.in/jcmturner/gokrb5.v7/keytab"
	"gopkg.in/jcmturner/gokrb5.v7/service"
	"gopkg.in/jcmturner/gokrb5.v7/spnego"
	"gopkg.in/jcmturner/gokrb5.v7/test/testdata"
)

const (
	port = ":9080"
)

func main() {
	//defer profile.Start(profile.TraceProfile).Stop()
	// Create logger
	l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)

	// Load the service's keytab
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)

	// Create the application's specific handler
	th := http.HandlerFunc(testAppHandler)

	// Set up handler mappings wrapping in the SPNEGOKRB5Authenticate handler wrapper
	mux := http.NewServeMux()
	mux.Handle("/", spnego.SPNEGOKRB5Authenticate(th, kt, service.Logger(l), service.SessionManager(NewSessionMgr("gokrb5"))))

	// Start up the web server
	log.Fatal(http.ListenAndServe(port, mux))
}

// Simple application specific handler
func testAppHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	ctx := r.Context()
	creds := ctx.Value(spnego.CTXKeyCredentials).(goidentity.Identity)
	fmt.Fprintf(w,
		`<html>
<h1>GOKRB5 Handler</h1>
<ul>
<li>Authenticed user: %s</li>
<li>User's realm: %s</li>
<li>Authn time: %v</li>
<li>Session ID: %s</li>
<ul>
</html>`,
		creds.UserName(),
		creds.Domain(),
		creds.AuthTime(),
		creds.SessionID(),
	)
	return
}

type SessionMgr struct {
	skey       []byte
	store      sessions.Store
	cookieName string
}

func NewSessionMgr(cookieName string) SessionMgr {
	skey := []byte("thisistestsecret") // Best practice is to load this key from a secure location.
	return SessionMgr{
		skey:       skey,
		store:      sessions.NewCookieStore(skey),
		cookieName: cookieName,
	}
}

func (smgr SessionMgr) Get(r *http.Request) (service.Session, error) {
	s, err := smgr.store.Get(r, smgr.cookieName)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, errors.New("nil session")
	}
	sess := Session(*s)
	return &sess, nil
}

func (smgr SessionMgr) New(w http.ResponseWriter, r *http.Request, k string, v []byte) error {
	s, err := smgr.store.New(r, smgr.cookieName)
	if err != nil {
		return fmt.Errorf("could not get new session from session manager: %v", err)
	}
	s.Values[k] = v
	return s.Save(r, w)
}

type Session sessions.Session

func (s *Session) Get(k string) []byte {
	b, ok := s.Values[k].([]byte)
	if !ok {
		return nil
	}
	return b
}
