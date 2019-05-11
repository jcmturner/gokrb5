// +build examples

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	goidentity "gopkg.in/jcmturner/goidentity.v3"
	"gopkg.in/jcmturner/gokrb5.v7/keytab"
	"gopkg.in/jcmturner/gokrb5.v7/service"
	"gopkg.in/jcmturner/gokrb5.v7/spnego"
	"gopkg.in/jcmturner/gokrb5.v7/test/testdata"
)

const (
	port = ":9080"
)

type SessionMgr struct {
	skey       []byte
	store      sessions.Store
	cookieName string
}

func NewSessionMgr(cookieName string) SessionMgr {
	skey := make([]byte, 32, 32)
	_, err := rand.Read(skey)
	if err != nil {
		log.Fatalf("could not create session cookie encryption key: %v", err)
	}
	return SessionMgr{
		skey:       skey,
		store:      sessions.NewCookieStore(skey),
		cookieName: cookieName,
	}
}

func (smgr SessionMgr) Get(r *http.Request) goidentity.Identity {
	var id goidentity.Identity
	s, err := smgr.store.Get(r, smgr.cookieName)
	if err != nil || s == nil {
		return id
	}
	id, ok := s.Values[spnego.CTXKeyCredentials].(goidentity.Identity)
	if !ok {
		return id
	}
	return id

}

func (smgr SessionMgr) New(w http.ResponseWriter, r *http.Request) error {
	s, err := smgr.store.Get(r, smgr.cookieName)
	if err != nil {
		return err
	}
	s.Values[spnego.CTXKeyCredentials] = r.Context().Value(spnego.CTXKeyCredentials)
	return s.Save(r, w)
}

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
	mux.Handle("/", spnego.SPNEGOKRB5Authenticate(th, kt, service.Logger(l)))

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
