// +build examples

package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/sessions"
	"gopkg.in/jcmturner/goidentity.v4"
	"gopkg.in/jcmturner/gokrb5.v7/spnego"
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
	b, ok := s.Values[spnego.CTXKeyCredentials].([]byte)
	if !ok {
		return id
	}
	var creds credentials.Credentials
	err = creds.Unmarshal(b)
	return id

}

func (smgr SessionMgr) New(w http.ResponseWriter, r *http.Request, id goidentity.Identity) error {
	s, err := smgr.store.Get(r, smgr.cookieName)
	if err != nil {
		return err
	}
	b, err := id.Marshal()
	if err != nil {
		return err
	}
	s.Values[spnego.CTXKeyCredentials] = b
	return s.Save(r, w)
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
