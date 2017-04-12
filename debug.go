package main

import (
	"encoding/hex"
	"fmt"
	"github.com/jcmturner/gokrb5/client"
	"github.com/jcmturner/gokrb5/config"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/service"
	"github.com/jcmturner/gokrb5/testdata"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"time"
)

const krb5conf = `[libdefaults]
  default_realm = TEST.GOKRB5
  dns_lookup_realm = false
  dns_lookup_kdc = false
  ticket_lifetime = 3m
  renew_lifetime = 7m
  forwardable = yes
  default_tkt_enctypes = aes256-cts-hmac-sha1-96

[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88
  admin_server = 10.80.88.88:749
  default_domain = test.gokrb5
 }

[domain_realm]
 .test.gokrb5 = TEST.GOKRB5
 test.gokrb5 = TEST.GOKRB5
 `

func main() {
	s := httpServer(false)
	defer s.Close()
	//httpRequest("http://host.test.gokrb5/index.html")
	httpRequest(s.URL)
	//runClient()
}

func runClient() {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(krb5conf)
	cl := client.NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error on AS_REQ: %v\n", err)
	}
	cl.EnableAutoSessionRenewal()
	for i := 0; i < 15; i++ {
		tkt, _, err := cl.GetServiceTicket("HTTP/host.test.gokrb5")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error on TGS_REQ: %v\n", err)
		} else {
			fmt.Fprintf(os.Stdout, "Service Ticket: %+v\n", tkt)
		}
		time.Sleep(time.Duration(1) * time.Minute)
	}
}

func httpRequest(url string) {
	l := log.New(os.Stderr, "GOKRB5 Client: ", log.Ldate|log.Ltime|log.Lshortfile)
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(krb5conf)
	cl := client.NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		l.Printf("Error on AS_REQ: %v\n", err)
	}
	r, _ := http.NewRequest("GET", url, nil)
	err = cl.SetSPNEGOHeader(r, "HTTP/host.test.gokrb5")
	if err != nil {
		l.Printf("Error setting client SPNEGO header: %v", err)
	}
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		l.Printf("Request error: %v\n", err)
	}
	fmt.Fprintf(os.Stdout, "RESPONSE CODE: %v\n", httpResp.StatusCode)
	content, _ := ioutil.ReadAll(httpResp.Body)
	fmt.Fprintf(os.Stdout, "ResponseBody: %s\n", content)
}

func httpServer(tls bool) *httptest.Server {
	l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)
	ks := "0502000000580002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b7262350000000158e7d0360300120020c2bcd4abcde0d2608d5f505e7ab5dc92df5f627e5819703c0b0f1d2c05d51c1600000003000000480002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b7262350000000158e7d0360300110010da152175c7a73f49e5ce4ece7068856400000003000000500002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b7262350000000158e7d03603001000187fc8ef5276e083da6bf89e676d7f98fd1acb9ec2cb20083d00000003000000480002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b7262350000000158e7d0360300170010011f2ef8e75e8378a94154beb002163200000003000000580002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b7262350000000158e7d03603001a0020f9db4e36aad9688d9ea30dbcc269c7ee46bf4f8bd6250f203a9f3836f0a673a600000003000000480002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b7262350000000158e7d0360300190010434981c9dce61ae1012f808bb60fc1c900000003000000400002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b7262350000000158e7d03603000800080b0d4f31e061529800000003000000400002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b7262350000000158e7d0360300030008f7df40f457aec42c00000003"
	b, _ := hex.DecodeString(ks)
	kt, _ := keytab.Parse(b)
	th := http.HandlerFunc(testAppHandler)
	if tls {
		s := httptest.NewTLSServer(service.SPNEGOKRB5Authenticate(th, kt, l))
		return s
	} else {
		s := httptest.NewServer(service.SPNEGOKRB5Authenticate(th, kt, l))
		return s
	}
}

func testAppHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "TEST.GOKRB5 Handler")
}
