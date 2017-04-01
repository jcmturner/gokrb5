package main

import (
	"encoding/hex"
	"fmt"
	"github.com/jcmturner/gokrb5/client"
	"github.com/jcmturner/gokrb5/config"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/testdata"
	"os"
	"time"
	"net/http"
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
	httpRequest()
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

func httpRequest() {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(krb5conf)
	cl := client.NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error on AS_REQ: %v\n", err)
	}
	r, _ := http.NewRequest("GET", "http://10.80.88.90/index.html", nil)
	cl.SetKRB5NegotiationHeader(r, "HTTP/host.test.gokrb5")
	httpResp, err := http.DefaultClient.Do(r)
	fmt.Fprintf(os.Stderr, "RESPONSE CODE: %v\n", httpResp.StatusCode)
}
