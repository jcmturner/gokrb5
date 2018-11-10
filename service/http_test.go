package service

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/goidentity.v3"
	"gopkg.in/jcmturner/gokrb5.v6/client"
	"gopkg.in/jcmturner/gokrb5.v6/iana/nametype"
	"gopkg.in/jcmturner/gokrb5.v6/keytab"
	"gopkg.in/jcmturner/gokrb5.v6/messages"
	"gopkg.in/jcmturner/gokrb5.v6/testdata"
	"gopkg.in/jcmturner/gokrb5.v6/types"
)

func TestService_SPNEGOKRB_NoAuthHeader(t *testing.T) {
	s := httpServer()
	defer s.Close()
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
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName, cl.Credentials.Realm,
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}

	r, _ := http.NewRequest("GET", s.URL, nil)
	err = client.SetSPNEGOHeader(*cl.Credentials, tkt, sessionKey, r)
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
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName, cl.Credentials.Realm,
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}

	r1, _ := http.NewRequest("GET", s.URL, nil)
	err = client.SetSPNEGOHeader(*cl.Credentials, tkt, sessionKey, r1)
	if err != nil {
		t.Fatalf("Error setting client SPNEGO header: %v", err)
	}

	// First request with this ticket should be accepted
	httpResp, err := http.DefaultClient.Do(r1)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")

	// Use ticket again should be rejected
	httpResp, err = http.DefaultClient.Do(r1)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected. Expected a replay to be detected.")

	// Form a 2nd ticket
	st = time.Now().UTC()
	tkt2, sessionKey2, err := messages.NewTicket(cl.Credentials.CName, cl.Credentials.Realm,
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	r2, _ := http.NewRequest("GET", s.URL, nil)
	err = client.SetSPNEGOHeader(*cl.Credentials, tkt2, sessionKey2, r2)
	if err != nil {
		t.Fatalf("Error setting client SPNEGO header: %v", err)
	}

	// First use of 2nd ticket should be accepted
	httpResp, err = http.DefaultClient.Do(r2)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")

	// Using the 1st ticket again should still be rejected
	httpResp, err = http.DefaultClient.Do(r1)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected. Expected a replay to be detected.")

	// Using the 2nd again should be rejected as replay
	httpResp, err = http.DefaultClient.Do(r2)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected. Expected a replay to be detected.")
}

func TestService_SPNEGOKRB_ReplayCache_Concurrency(t *testing.T) {
	s := httpServer()
	defer s.Close()

	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName, cl.Credentials.Realm,
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}

	r1, _ := http.NewRequest("GET", s.URL, nil)
	err = client.SetSPNEGOHeader(*cl.Credentials, tkt, sessionKey, r1)
	if err != nil {
		t.Fatalf("Error setting client SPNEGO header: %v", err)
	}

	// Form a 2nd ticket
	st = time.Now().UTC()
	tkt2, sessionKey2, err := messages.NewTicket(cl.Credentials.CName, cl.Credentials.Realm,
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	r2, _ := http.NewRequest("GET", s.URL, nil)
	err = client.SetSPNEGOHeader(*cl.Credentials, tkt2, sessionKey2, r2)
	if err != nil {
		t.Fatalf("Error setting client SPNEGO header: %v", err)
	}

	// Concurrent 1st requests should be OK
	var wg sync.WaitGroup
	wg.Add(2)
	go httpGet(r1, &wg)
	go httpGet(r2, &wg)
	wg.Wait()

	// A number of concurrent requests with the same ticket should be rejected due to replay
	var wg2 sync.WaitGroup
	noReq := 10
	wg2.Add(noReq * 2)
	for i := 0; i < noReq; i++ {
		go httpGet(r1, &wg2)
		go httpGet(r2, &wg2)
	}
	wg2.Wait()
}

func TestService_SPNEGOKRB_Upload(t *testing.T) {
	s := httpServer()
	defer s.Close()

	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName, cl.Credentials.Realm,
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}

	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	fileWriter, err := bodyWriter.CreateFormFile("uploadfile", "testfile.bin")
	if err != nil {
		t.Fatalf("error writing to buffer: %v", err)
	}

	data := make([]byte, 10240)
	rand.Read(data)
	br := bytes.NewReader(data)
	_, err = io.Copy(fileWriter, br)
	if err != nil {
		t.Fatalf("error copying bytes: %v", err)
	}
	bodyWriter.Close()

	r, _ := http.NewRequest("POST", s.URL, bodyBuf)
	err = client.SetSPNEGOHeader(*cl.Credentials, tkt, sessionKey, r)
	if err != nil {
		t.Fatalf("Error setting client SPNEGO header: %v", err)
	}
	r.Header.Set("Content-Type", bodyWriter.FormDataContentType())
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(httpResp.Body)
		bodyString := string(bodyBytes)
		httpResp.Body.Close()
		t.Errorf("unexpected code from http server (%d): %s", httpResp.StatusCode, bodyString)
	}
}

func httpGet(r *http.Request, wg *sync.WaitGroup) {
	defer wg.Done()
	http.DefaultClient.Do(r)
}

func httpServer() *httptest.Server {
	l := log.New(ioutil.Discard, "GOKRB5 Service Tests: ", log.Ldate|log.Ltime|log.Lshortfile)
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	th := http.HandlerFunc(testAppHandler)
	c := NewConfig(kt)
	s := httptest.NewServer(SPNEGOKRB5Authenticate(th, c, l))
	return s
}

func testAppHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		maxUploadSize := int64(11240)
		if err := r.ParseMultipartForm(maxUploadSize); err != nil {
			http.Error(w, fmt.Sprintf("cannot parse multipart form: %v", err), http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
		file, _, err := r.FormFile("uploadfile")
		if err != nil {
			http.Error(w, "INVALID_FILE", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// write out to /dev/null
		_, err = io.Copy(ioutil.Discard, file)
		if err != nil {
			http.Error(w, "WRITE_ERR", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	ctx := r.Context()
	fmt.Fprintf(w, "<html>\nTEST.GOKRB5 Handler\nAuthenticed user: %s\nUser's realm: %s\n</html>",
		ctx.Value(CTXKeyCredentials).(goidentity.Identity).UserName(),
		ctx.Value(CTXKeyCredentials).(goidentity.Identity).Domain())
	return
}
