// +build examples

package main

import (
	"encoding/hex"
	"fmt"
	"github.com/jcmturner/gokrb5/client"
	"github.com/jcmturner/gokrb5/config"
	"github.com/jcmturner/gokrb5/credentials"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/service"
	"github.com/jcmturner/gokrb5/testdata"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
)

func main() {
	s := httpServer()
	defer s.Close()

	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF_AD)
	cl := client.NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)
	httpRequest(s.URL, cl)

	b, _ = hex.DecodeString(testdata.TESTUSER2_KEYTAB)
	kt, _ = keytab.Parse(b)
	c, _ = config.NewConfigFromString(testdata.TEST_KRB5CONF_AD)
	cl = client.NewClientWithKeytab("testuser2", "TEST.GOKRB5", kt)
	cl.WithConfig(c)
	httpRequest(s.URL, cl)

	//httpRequest("http://host.test.gokrb5/index.html")
}

func httpRequest(url string, cl client.Client) {
	l := log.New(os.Stderr, "GOKRB5 Client: ", log.Ldate|log.Ltime|log.Lshortfile)

	err := cl.Login()
	if err != nil {
		l.Printf("Error on AS_REQ: %v\n", err)
	}
	cl.EnableAutoSessionRenewal()
	r, _ := http.NewRequest("GET", url, nil)
	err = cl.SetSPNEGOHeader(r, "HTTP/host.test.gokrb5")
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
	l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)
	b, _ := hex.DecodeString(testdata.SYSHTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	th := http.HandlerFunc(testAppHandler)
	s := httptest.NewServer(service.SPNEGOKRB5Authenticate(th, kt, "sysHTTP", l))
	return s
}

func testAppHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fmt.Fprint(w, "<html>\n<p><h1>TEST.GOKRB5 Handler</h1></p>\n")
	if validuser, ok := ctx.Value("authenticated").(bool); ok && validuser {
		if creds, ok := ctx.Value("credentials").(credentials.Credentials); ok {
			fmt.Fprintf(w, "<ul><li>Authenticed user: %s</li>\n", creds.Username)
			fmt.Fprintf(w, "<li>User's realm: %s</li>\n", creds.Realm)
			if ADCreds, ok := creds.Attributes["ADCredentials"].(credentials.ADCredentials); ok {
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
			fmt.Fprint(w, "</ul>")
		}

	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Authentication failed")
	}
	fmt.Fprint(w, "</html>")
	return
}
