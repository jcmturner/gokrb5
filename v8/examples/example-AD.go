// +build examples

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
)

func main() {
	s := httpServer()
	defer s.Close()

	b, _ := hex.DecodeString(testdata.TESTUSER1_USERKRB5_AD_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.TEST_KRB5CONF)
	cl := client.NewWithKeytab("testuser1", "USER.GOKRB5", kt, c, client.DisablePAFXFAST(true))
	httpRequest(s.URL, cl)

	b, _ = hex.DecodeString(testdata.TESTUSER2_USERKRB5_AD_KEYTAB)
	kt = keytab.New()
	kt.Unmarshal(b)
	c, _ = config.NewFromString(testdata.TEST_KRB5CONF)
	cl = client.NewWithKeytab("testuser2", "USER.GOKRB5", kt, c, client.DisablePAFXFAST(true))
	httpRequest(s.URL, cl)

	//httpRequest("http://host.test.gokrb5/index.html")
}

func httpRequest(url string, cl *client.Client) {
	l := log.New(os.Stderr, "GOKRB5 Client: ", log.Ldate|log.Ltime|log.Lshortfile)

	err := cl.Login()
	if err != nil {
		l.Printf("Error on AS_REQ: %v\n", err)
	}
	r, _ := http.NewRequest("GET", url, nil)
	err = spnego.SetSPNEGOHeader(cl, r, "HTTP/host.test.gokrb5")
	if err != nil {
		l.Printf("Error setting client SPNEGO header: %v", err)
	}
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		l.Printf("Request error: %v\n", err)
	}
	fmt.Fprintf(os.Stdout, "Response Code: %v\n", httpResp.StatusCode)
	content, _ := ioutil.ReadAll(httpResp.Body)
	fmt.Fprintf(os.Stdout, "Response Body:\n%s\n", content)
}

func httpServer() *httptest.Server {
	l := log.New(os.Stderr, "GOKRB5 Service Tests: ", log.Ldate|log.Ltime|log.Lshortfile)
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	th := http.HandlerFunc(testAppHandler)
	s := httptest.NewServer(spnego.SPNEGOKRB5Authenticate(th, kt, service.Logger(l)))
	return s
}

func testAppHandler(w http.ResponseWriter, r *http.Request) {
	creds := goidentity.FromHTTPRequestContext(r)
	fmt.Fprint(w, "<html>\n<p><h1>TEST.GOKRB5 Handler</h1></p>\n")
	if creds != nil && creds.Authenticated() {
		fmt.Fprintf(w, "<ul><li>Authenticed user: %s</li>\n", creds.UserName())
		fmt.Fprintf(w, "<li>User's realm: %s</li>\n", creds.Domain())
		fmt.Fprint(w, "<li>Authz Attributes (Group Memberships):</li><ul>\n")
		for _, s := range creds.AuthzAttributes() {
			fmt.Fprintf(w, "<li>%v</li>\n", s)
		}
		fmt.Fprint(w, "</ul>\n")
		if ADCredsJSON, ok := creds.Attributes()[credentials.AttributeKeyADCredentials]; ok {
			ADCreds := new(credentials.ADCredentials)
			err := json.Unmarshal([]byte(ADCredsJSON), ADCreds)
			if err == nil {
				// Now access the fields of the ADCredentials struct. For example:
				fmt.Fprintf(w, "<li>EffectiveName: %v</li>\n", ADCreds.EffectiveName)
				fmt.Fprintf(w, "<li>FullName: %v</li>\n", ADCreds.FullName)
				fmt.Fprintf(w, "<li>UserID: %v</li>\n", ADCreds.UserID)
				fmt.Fprintf(w, "<li>PrimaryGroupID: %v</li>\n", ADCreds.PrimaryGroupID)
				fmt.Fprintf(w, "<li>Group SIDs: %v</li>\n", ADCreds.GroupMembershipSIDs)
				fmt.Fprintf(w, "<li>LogOnTime: %v</li>\n", ADCreds.LogOnTime)
				fmt.Fprintf(w, "<li>LogOffTime: %v</li>\n", ADCreds.LogOffTime)
				fmt.Fprintf(w, "<li>PasswordLastSet: %v</li>\n", ADCreds.PasswordLastSet)
				fmt.Fprintf(w, "<li>LogonServer: %v</li>\n", ADCreds.LogonServer)
				fmt.Fprintf(w, "<li>LogonDomainName: %v</li>\n", ADCreds.LogonDomainName)
				fmt.Fprintf(w, "<li>LogonDomainID: %v</li>\n", ADCreds.LogonDomainID)
			}
		}
		fmt.Fprint(w, "</ul>")
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Authentication failed")
	}
	fmt.Fprint(w, "</html>")
	return
}
