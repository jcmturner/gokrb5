// +build integration
// To turn on this test use -tags=integration in go test command

package service

import (
	"encoding/hex"
	"fmt"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/testdata"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestService_SPNEGOKRB_NoAuthHeader(t *testing.T) {
	s := httpServer()
	defer s.Close()

	cl := getClient()
	err := cl.Login()
	if err != nil {
		t.Fatalf("Error on AS_REQ: %v\n", err)
	}
	r, _ := http.NewRequest("GET", s.URL, nil)
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected")
	assert.Equal(t, "Negotiate", httpResp.Header.Get("WWW-Authenticate"), "Negitation header not set by server.")
}

func TestService_SPNEGOKRB_ValidUser(t *testing.T) {
	s := httpServer()
	defer s.Close()

	cl := getClient()
	err := cl.Login()
	if err != nil {
		t.Fatalf("Error on AS_REQ: %v\n", err)
	}
	r, _ := http.NewRequest("GET", s.URL, nil)
	err = cl.SetSPNEGOHeader(r, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("Error setting client SPNEGO header: %v", err)
	}
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")
}

func TestService_SPNEGOKRB_Replay(t *testing.T) {
	s := httpServer()
	defer s.Close()

	cl := getClient()
	err := cl.Login()
	if err != nil {
		t.Fatalf("Error on AS_REQ: %v\n", err)
	}
	r, _ := http.NewRequest("GET", s.URL, nil)
	err = cl.SetSPNEGOHeader(r, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("Error setting client SPNEGO header: %v", err)
	}

	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")

	// Do not Set the SPNEGO header again so this should try to replay the tokens
	httpResp, err = http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected. Expected a replay to be detected.")
}

func httpServer() *httptest.Server {
	l := log.New(ioutil.Discard, "GOKRB5 Service Tests: ", log.Ldate|log.Ltime|log.Lshortfile)
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	th := http.HandlerFunc(testAppHandler)
	s := httptest.NewServer(SPNEGOKRB5Authenticate(th, kt, l))
	return s
}

func testAppHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	ctx := r.Context()
	fmt.Fprintf(w, "<html>\nTEST.GOKRB5 Handler\nAuthenticed user: %s\nUser's realm: %s\n</html>", ctx.Value("cname").(string), ctx.Value("crealm").(string))
	return
}
