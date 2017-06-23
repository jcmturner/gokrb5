package config

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

const krb5Conf = `
[logging]
 default = FILE:/var/log/kerberos/krb5libs.log
 kdc = FILE:/var/log/kerberos/krb5kdc.log
 admin_server = FILE:/var/log/kerberos/kadmind.log

[libdefaults]
 default_realm = TEST.GOKRB5
 dns_lookup_realm = false

 dns_lookup_kdc = false
 #dns_lookup_kdc = true
 ;dns_lookup_kdc = true
#dns_lookup_kdc = true
;dns_lookup_kdc = true
 ticket_lifetime = 10h
 forwardable = yes
 default_keytab_name = FILE:/etc/krb5.keytab

 default_client_keytab_name = FILE:/home/gokrb5/client.keytab
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96


[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88

  kdc = 10.80.88.88:88*
  kdc = 10.1.2.3.4:88

  admin_server = 10.80.88.88:749
  default_domain = test.gokrb5
 }
 EXAMPLE.COM = {
        kdc = kerberos.example.com
        kdc = kerberos-1.example.com
        admin_server = kerberos.example.com
 }


[domain_realm]
 .test.gokrb5 = TEST.GOKRB5

 test.gokrb5 = TEST.GOKRB5

[appdefaults]
 pam = {
   debug = false

   ticket_lifetime = 36000

   renew_lifetime = 36000
   forwardable = true
   krb4_convert = false
 }
`

func TestLoad(t *testing.T) {
	cf, _ := ioutil.TempFile(os.TempDir(), "TEST-gokrb5-krb5.conf")
	defer os.Remove(cf.Name())
	cf.WriteString(krb5Conf)

	c, err := Load(cf.Name())
	if err != nil {
		t.Fatalf("Error loading config: %v", err)
	}

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.Default_realm, "[libdefaults] default_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.Dns_lookup_realm, "[libdefaults] dns_lookup_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.Dns_lookup_kdc, "[libdefaults] dns_lookup_kdc not as expected")
	assert.Equal(t, time.Duration(10)*time.Hour, c.LibDefaults.Ticket_lifetime, "[libdefaults] Ticket lifetime not as expected")
	assert.Equal(t, true, c.LibDefaults.Forwardable, "[libdefaults] forwardable not as expected")
	assert.Equal(t, "FILE:/etc/krb5.keytab", c.LibDefaults.Default_keytab_name, "[libdefaults] default_keytab_name not as expected")
	assert.Equal(t, "FILE:/home/gokrb5/client.keytab", c.LibDefaults.Default_client_keytab_name, "[libdefaults] default_client_keytab_name not as expected")
	assert.Equal(t, []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}, c.LibDefaults.Default_tkt_enctypes, "[libdefaults] default_tkt_enctypes not as expected")

	assert.Equal(t, 2, len(c.Realms), "Number of realms not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.Realms[0].Realm, "[realm] realm name not as expectd")
	assert.Equal(t, []string{"10.80.88.88:749"}, c.Realms[0].Admin_server, "[realm] Admin_server not as expectd")
	assert.Equal(t, []string{"10.80.88.88:464"}, c.Realms[0].Kpasswd_server, "[realm] Kpasswd_server not as expectd")
	assert.Equal(t, "test.gokrb5", c.Realms[0].Default_domain, "[realm] Default_domain not as expectd")
	assert.Equal(t, []string{"10.80.88.88:88", "10.80.88.88:88"}, c.Realms[0].Kdc, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com", "kerberos-1.example.com"}, c.Realms[1].Kdc, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com"}, c.Realms[1].Admin_server, "[realm] Admin_server not as expectd")

	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm[".test.gokrb5"], "Domain to realm mapping not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm["test.gokrb5"], "Domain to realm mapping not as expected")

}
