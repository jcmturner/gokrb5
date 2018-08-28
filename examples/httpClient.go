// +build examples

package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	//"github.com/pkg/profile"
	"gopkg.in/jcmturner/gokrb5.v6/client"
	"gopkg.in/jcmturner/gokrb5.v6/config"
	"gopkg.in/jcmturner/gokrb5.v6/keytab"
	"gopkg.in/jcmturner/gokrb5.v6/testdata"
)

const (
	port     = ":9080"
	kRB5CONF = `[libdefaults]
  default_realm = TEST.GOKRB5
  dns_lookup_realm = false
  dns_lookup_kdc = false
  ticket_lifetime = 24h
  forwardable = yes
  default_tkt_enctypes = aes256-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96

[realms]
 TEST.GOKRB5 = {
  kdc = 127.0.0.1:88
  admin_server = 127.0.0.1:749
  default_domain = test.gokrb5
 }

[domain_realm]
 .test.gokrb5 = TEST.GOKRB5
 test.gokrb5 = TEST.GOKRB5
 `
)

func main() {
	//defer profile.Start(profile.TraceProfile).Stop()
	// Load the keytab
	kb, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, err := keytab.Parse(kb)
	if err != nil {
		panic(err)
	}

	// Create the client with the keytab
	cl := client.NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)

	// Load the client krb5 config
	conf, err := config.NewConfigFromString(kRB5CONF)
	if err != nil {
		panic(err)
	}
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr != "" {
		conf.Realms[0].KDC = []string{addr + ":88"}
	}
	// Apply the config to the client
	cl.WithConfig(conf)

	// Log in the client
	err = cl.Login()
	if err != nil {
		panic(err)
	}

	// Form the request
	url := "http://localhost" + port
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}
	// Apply the client's auth headers to the request
	err = cl.SetSPNEGOHeader(r, "HTTP/host.test.gokrb5")
	if err != nil {
		panic(err)
	}

	// Make the request
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		panic(err)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
}
