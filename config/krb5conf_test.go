package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	krb5ConfIncHead = `
# To opt out of the system crypto-policies configuration of krb5, remove the
# symlink at /etc/krb5.conf.d/crypto-policies which will not be recreated.
#includedir /etc/krb5.conf.d/
`

	krb5ConfInc = `
[logging]
    default = FILE:/var/log/krb5libs.log
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log

[libdefaults]
    dns_lookup_realm = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    pkinit_anchors = FILE:/etc/pki/tls/certs/ca-bundle.crt
    spake_preauth_groups = edwards25519
#    default_realm = EXAMPLE.COM
    default_ccache_name = KEYRING:persistent:%{uid}

[realms]
# EXAMPLE.COM = {
#     kdc = kerberos.example.com
#     admin_server = kerberos.example.com
# }

[domain_realm]
# .example.com = EXAMPLE.COM
# example.com = EXAMPLE.COM
`
	krb5ConfIHead = `
[logging]
 default = FILE:/var/log/kerberos/krb5libs.log
 kdc = FILE:/var/log/kerberos/krb5kdc.log
 admin_server = FILE:/var/log/kerberos/kadmind.log

`
	krb5Include = `
[libdefaults]
 default_realm = TEST.GOKRB5 ; comment to be ignored
 dns_lookup_realm = false

 dns_lookup_kdc = false
 #dns_lookup_kdc = true
 ;dns_lookup_kdc = true
#dns_lookup_kdc = true
;dns_lookup_kdc = true
 ticket_lifetime = 10h ;comment to be ignored
 forwardable = yes #comment to be ignored
 default_keytab_name = FILE:/etc/krb5.keytab

 default_client_keytab_name = FILE:/home/gokrb5/client.keytab
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 # comment to be ignored

`
	krb5ConfI = `
[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88 #comment to be ignored
  kdc = assume.port.num ;comment to be ignored
  kdc = some.other.port:1234 # comment to be ignored

  kdc = 10.80.88.88*
  kdc = 10.1.2.3.4:88

  admin_server = 10.80.88.88:749 ; comment to be ignored
  default_domain = test.gokrb5
 }
 EXAMPLE.COM = {
        kdc = kerberos.example.com
        kdc = kerberos-1.example.com
        admin_server = kerberos.example.com
        auth_to_local = RULE:[1:$1@$0](.*@EXAMPLE.COM)s/.*//
 }
 lowercase.org = {
  kdc = kerberos.lowercase.org
  admin_server = kerberos.lowercase.org
 }


[domain_realm]
 .test.gokrb5 = TEST.GOKRB5 #comment to be ignored

 test.gokrb5 = TEST.GOKRB5 ;comment to be ignored
 
  .example.com = EXAMPLE.COM # comment to be ignored
 hostname1.example.com = EXAMPLE.COM ; comment to be ignored
 hostname2.example.com = TEST.GOKRB5
 .testlowercase.org = lowercase.org


[appdefaults]
 pam = {
   debug = false

   ticket_lifetime = 36000

   renew_lifetime = 36000
   forwardable = true
   krb4_convert = false
 }
`

	krb5Conf = `
[logging]
 default = FILE:/var/log/kerberos/krb5libs.log
 kdc = FILE:/var/log/kerberos/krb5kdc.log
 admin_server = FILE:/var/log/kerberos/kadmind.log

[libdefaults]
 default_realm = TEST.GOKRB5 ; comment to be ignored
 dns_lookup_realm = false

 dns_lookup_kdc = false
 #dns_lookup_kdc = true
 ;dns_lookup_kdc = true
#dns_lookup_kdc = true
;dns_lookup_kdc = true
 ticket_lifetime = 10h ;comment to be ignored
 forwardable = yes #comment to be ignored
 default_keytab_name = FILE:/etc/krb5.keytab

 default_client_keytab_name = FILE:/home/gokrb5/client.keytab
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 # comment to be ignored


[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88 #comment to be ignored
  kdc = assume.port.num ;comment to be ignored
  kdc = some.other.port:1234 # comment to be ignored

  kdc = 10.80.88.88*
  kdc = 10.1.2.3.4:88

  admin_server = 10.80.88.88:749 ; comment to be ignored
  default_domain = test.gokrb5
 }
 EXAMPLE.COM = {
        kdc = kerberos.example.com
        kdc = kerberos-1.example.com
        admin_server = kerberos.example.com
        auth_to_local = RULE:[1:$1@$0](.*@EXAMPLE.COM)s/.*//
 }
 lowercase.org = {
  kdc = kerberos.lowercase.org
  admin_server = kerberos.lowercase.org
 }


[domain_realm]
 .test.gokrb5 = TEST.GOKRB5 #comment to be ignored

 test.gokrb5 = TEST.GOKRB5 ;comment to be ignored
 
  .example.com = EXAMPLE.COM # comment to be ignored
 hostname1.example.com = EXAMPLE.COM ; comment to be ignored
 hostname2.example.com = TEST.GOKRB5
 .testlowercase.org = lowercase.org


[appdefaults]
 pam = {
   debug = false

   ticket_lifetime = 36000

   renew_lifetime = 36000
   forwardable = true
   krb4_convert = false
 }
`
	krb5Conf2 = `
[logging]
 default = FILE:/var/log/kerberos/krb5libs.log
 kdc = FILE:/var/log/kerberos/krb5kdc.log
 admin_server = FILE:/var/log/kerberos/kadmind.log

[libdefaults]
 noaddresses = true
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
 [realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88
  kdc = assume.port.num
  kdc = some.other.port:1234

  kdc = 10.80.88.88*
  kdc = 10.1.2.3.4:88

  admin_server = 10.80.88.88:749
  default_domain = test.gokrb5
 }
 EXAMPLE.COM = {
        kdc = kerberos.example.com
        kdc = kerberos-1.example.com
        admin_server = kerberos.example.com
 }
`
	krb5ConfNoBlankLines = `
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
  kdc = assume.port.num
  kdc = some.other.port:1234
  kdc = 10.80.88.88*
  kdc = 10.1.2.3.4:88
  admin_server = 10.80.88.88:749
  default_domain = test.gokrb5
 }
 EXAMPLE.COM = {
        kdc = kerberos.example.com
        kdc = kerberos-1.example.com
        admin_server = kerberos.example.com
        auth_to_local = RULE:[1:$1@$0](.*@EXAMPLE.COM)s/.*//
 }
[domain_realm]
 .test.gokrb5 = TEST.GOKRB5
 test.gokrb5 = TEST.GOKRB5
`
	krb5ConfTabs = `
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
		kdc = assume.port.num
		kdc = some.other.port:1234

		kdc = 10.80.88.88*
		kdc = 10.1.2.3.4:88

		admin_server = 10.80.88.88:749
		default_domain = test.gokrb5
	}
	EXAMPLE.COM = {
		kdc = kerberos.example.com
		kdc = kerberos-1.example.com
		admin_server = kerberos.example.com
		auth_to_local = RULE:[1:$1@$0](.*@EXAMPLE.COM)s/.*//
	}


[domain_realm]
	.test.gokrb5 = TEST.GOKRB5

	test.gokrb5 = TEST.GOKRB5
 
	.example.com = EXAMPLE.COM
	hostname1.example.com = EXAMPLE.COM
	hostname2.example.com = TEST.GOKRB5


[appdefaults]
	pam = {
	debug = false

	ticket_lifetime = 36000

	renew_lifetime = 36000
	forwardable = true
	krb4_convert = false
}`

	krb5ConfV4Lines = `
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
  kdc = assume.port.num
  kdc = some.other.port:1234

  kdc = 10.80.88.88*
  kdc = 10.1.2.3.4:88

  admin_server = 10.80.88.88:749
  default_domain = test.gokrb5
    v4_name_convert = {
     host = {
        rcmd = host
     }
   }
 }
 EXAMPLE.COM = {
        kdc = kerberos.example.com
        kdc = kerberos-1.example.com
        admin_server = kerberos.example.com
        auth_to_local = RULE:[1:$1@$0](.*@EXAMPLE.COM)s/.*//
 }


[domain_realm]
 .test.gokrb5 = TEST.GOKRB5

 test.gokrb5 = TEST.GOKRB5
 
  .example.com = EXAMPLE.COM
 hostname1.example.com = EXAMPLE.COM
 hostname2.example.com = TEST.GOKRB5


[appdefaults]
 pam = {
   debug = false

   ticket_lifetime = 36000

   renew_lifetime = 36000
   forwardable = true
   krb4_convert = false
 }
`
)

func TestLoadincludedir(t *testing.T) {
	t.Parallel()
	cf, _ := ioutil.TempFile(os.TempDir(), "TEST-gokrb5-krb5inc.conf")
	defer os.Remove(cf.Name())
	cdir, _ := ioutil.TempDir("", "example")
	defer os.RemoveAll(cdir)
	cfgDir := "testkrb5.conf.d"
	files, err := os.ReadDir(cfgDir)
	if err != nil {
		t.Fatalf("Error loading config dir: %v", err)
	}
	for _, file := range files {
		srcPath := filepath.Join(cfgDir, file.Name())
		data, err := ioutil.ReadFile(srcPath)
		if err != nil {
			t.Fatalf("Error reading config file: %v", err)
		}
		dstPath := filepath.Join(cdir, file.Name())
		err = ioutil.WriteFile(dstPath, data, 0644)
		if err != nil {
			t.Fatalf("Error writting config file: %v", err)
		}
	}
	krb5ContentsInc := krb5ConfIncHead + fmt.Sprintf("includedir %s\n", cdir) + krb5ConfInc
	cf.WriteString(krb5ContentsInc)

	c, err := Load(cf.Name())
	if err != nil {
		t.Fatalf("Error loading config: %v", err)
	}

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm, "[libdefaults] default_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupRealm, "[libdefaults] dns_lookup_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupKDC, "[libdefaults] dns_lookup_kdc not as expected")
	assert.Equal(t, time.Duration(24)*time.Hour, c.LibDefaults.TicketLifetime, "[libdefaults] Ticket lifetime not as expected")
	assert.Equal(t, true, c.LibDefaults.Forwardable, "[libdefaults] forwardable not as expected")
	assert.Equal(t, "/etc/krb5.keytab", c.LibDefaults.DefaultKeytabName, "[libdefaults] default_keytab_name not as expected")
	assert.Equal(t, "FILE:/home/gokrb5/client.keytab", c.LibDefaults.DefaultClientKeytabName, "[libdefaults] default_client_keytab_name not as expected")
	assert.Equal(t, []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "des3-cbc-sha1", "arcfour-hmac-md5", "camellia256-cts-cmac", "camellia128-cts-cmac", "des-cbc-crc", "des-cbc-md5", "des-cbc-md4"}, c.LibDefaults.DefaultTktEnctypes, "[libdefaults] default_tkt_enctypes not as expected")
	assert.Equal(t, 7, len(c.Realms), "Number of realms not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.Realms[6].Realm, "[realm] realm name not as expectd")
	assert.Equal(t, []string{"cndc.test.gokrb5"}, c.Realms[6].AdminServer, "[realm] Admin_server not as expectd")
	assert.Equal(t, []string{"cndc.test.gokrb5"}, c.Realms[6].KPasswdServer, "[realm] Kpasswd_server not as expectd")
	assert.Equal(t, "test.gokrb5", c.Realms[6].DefaultDomain, "[realm] Default_domain not as expectd")
	assert.Equal(t, []string{"cndc.test.gokrb5:88"}, c.Realms[6].KDC, "[realm] Kdc not as expectd")

}

func TestLoadinclude(t *testing.T) {
	t.Parallel()
	cf, _ := ioutil.TempFile(os.TempDir(), "TEST-gokrb5-krb5inc.conf")
	defer os.Remove(cf.Name())
	incf, _ := ioutil.TempFile(os.TempDir(), "TEST-gokrb5-krb5include")
	defer os.Remove(incf.Name())
	incf.WriteString(krb5Include)
	krb5ContentsI := krb5ConfIHead + fmt.Sprintf("include %s\n", incf.Name()) + krb5ConfI
	cf.WriteString(krb5ContentsI)

	c, err := Load(cf.Name())
	if err != nil {
		t.Fatalf("Error loading config: %v", err)
	}

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm, "[libdefaults] default_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupRealm, "[libdefaults] dns_lookup_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupKDC, "[libdefaults] dns_lookup_kdc not as expected")
	assert.Equal(t, time.Duration(10)*time.Hour, c.LibDefaults.TicketLifetime, "[libdefaults] Ticket lifetime not as expected")
	assert.Equal(t, true, c.LibDefaults.Forwardable, "[libdefaults] forwardable not as expected")
	assert.Equal(t, "FILE:/etc/krb5.keytab", c.LibDefaults.DefaultKeytabName, "[libdefaults] default_keytab_name not as expected")
	assert.Equal(t, "FILE:/home/gokrb5/client.keytab", c.LibDefaults.DefaultClientKeytabName, "[libdefaults] default_client_keytab_name not as expected")
	assert.Equal(t, []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}, c.LibDefaults.DefaultTktEnctypes, "[libdefaults] default_tkt_enctypes not as expected")

	assert.Equal(t, 3, len(c.Realms), "Number of realms not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.Realms[0].Realm, "[realm] realm name not as expectd")
	assert.Equal(t, []string{"10.80.88.88:749"}, c.Realms[0].AdminServer, "[realm] Admin_server not as expectd")
	assert.Equal(t, []string{"10.80.88.88:464"}, c.Realms[0].KPasswdServer, "[realm] Kpasswd_server not as expectd")
	assert.Equal(t, "test.gokrb5", c.Realms[0].DefaultDomain, "[realm] Default_domain not as expectd")
	assert.Equal(t, []string{"10.80.88.88:88", "assume.port.num:88", "some.other.port:1234", "10.80.88.88:88"}, c.Realms[0].KDC, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com:88", "kerberos-1.example.com:88"}, c.Realms[1].KDC, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com"}, c.Realms[1].AdminServer, "[realm] Admin_server not as expectd")

	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm[".test.gokrb5"], "Domain to realm mapping not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm["test.gokrb5"], "Domain to realm mapping not as expected")

}

func TestLoad(t *testing.T) {
	t.Parallel()
	cf, _ := ioutil.TempFile(os.TempDir(), "TEST-gokrb5-krb5.conf")
	defer os.Remove(cf.Name())
	cf.WriteString(krb5Conf)

	c, err := Load(cf.Name())
	if err != nil {
		t.Fatalf("Error loading config: %v", err)
	}

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm, "[libdefaults] default_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupRealm, "[libdefaults] dns_lookup_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupKDC, "[libdefaults] dns_lookup_kdc not as expected")
	assert.Equal(t, time.Duration(10)*time.Hour, c.LibDefaults.TicketLifetime, "[libdefaults] Ticket lifetime not as expected")
	assert.Equal(t, true, c.LibDefaults.Forwardable, "[libdefaults] forwardable not as expected")
	assert.Equal(t, "FILE:/etc/krb5.keytab", c.LibDefaults.DefaultKeytabName, "[libdefaults] default_keytab_name not as expected")
	assert.Equal(t, "FILE:/home/gokrb5/client.keytab", c.LibDefaults.DefaultClientKeytabName, "[libdefaults] default_client_keytab_name not as expected")
	assert.Equal(t, []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}, c.LibDefaults.DefaultTktEnctypes, "[libdefaults] default_tkt_enctypes not as expected")

	assert.Equal(t, 3, len(c.Realms), "Number of realms not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.Realms[0].Realm, "[realm] realm name not as expectd")
	assert.Equal(t, []string{"10.80.88.88:749"}, c.Realms[0].AdminServer, "[realm] Admin_server not as expectd")
	assert.Equal(t, []string{"10.80.88.88:464"}, c.Realms[0].KPasswdServer, "[realm] Kpasswd_server not as expectd")
	assert.Equal(t, "test.gokrb5", c.Realms[0].DefaultDomain, "[realm] Default_domain not as expectd")
	assert.Equal(t, []string{"10.80.88.88:88", "assume.port.num:88", "some.other.port:1234", "10.80.88.88:88"}, c.Realms[0].KDC, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com:88", "kerberos-1.example.com:88"}, c.Realms[1].KDC, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com"}, c.Realms[1].AdminServer, "[realm] Admin_server not as expectd")

	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm[".test.gokrb5"], "Domain to realm mapping not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm["test.gokrb5"], "Domain to realm mapping not as expected")

}

func TestLoadWithV4Lines(t *testing.T) {
	t.Parallel()
	cf, _ := ioutil.TempFile(os.TempDir(), "TEST-gokrb5-krb5.conf")
	defer os.Remove(cf.Name())
	cf.WriteString(krb5ConfV4Lines)

	c, err := Load(cf.Name())
	if err == nil {
		t.Fatalf("error should not be nil for config that includes v4 lines")
	}
	if _, ok := err.(UnsupportedDirective); !ok {
		t.Fatalf("error should be of type UnsupportedDirective: %v", err)
	}

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm, "[libdefaults] default_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupRealm, "[libdefaults] dns_lookup_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupKDC, "[libdefaults] dns_lookup_kdc not as expected")
	assert.Equal(t, time.Duration(10)*time.Hour, c.LibDefaults.TicketLifetime, "[libdefaults] Ticket lifetime not as expected")
	assert.Equal(t, true, c.LibDefaults.Forwardable, "[libdefaults] forwardable not as expected")
	assert.Equal(t, "FILE:/etc/krb5.keytab", c.LibDefaults.DefaultKeytabName, "[libdefaults] default_keytab_name not as expected")
	assert.Equal(t, "FILE:/home/gokrb5/client.keytab", c.LibDefaults.DefaultClientKeytabName, "[libdefaults] default_client_keytab_name not as expected")
	assert.Equal(t, []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}, c.LibDefaults.DefaultTktEnctypes, "[libdefaults] default_tkt_enctypes not as expected")

	assert.Equal(t, 2, len(c.Realms), "Number of realms not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.Realms[0].Realm, "[realm] realm name not as expectd")
	assert.Equal(t, []string{"10.80.88.88:749"}, c.Realms[0].AdminServer, "[realm] Admin_server not as expectd")
	assert.Equal(t, []string{"10.80.88.88:464"}, c.Realms[0].KPasswdServer, "[realm] Kpasswd_server not as expectd")
	assert.Equal(t, "test.gokrb5", c.Realms[0].DefaultDomain, "[realm] Default_domain not as expectd")
	assert.Equal(t, []string{"10.80.88.88:88", "assume.port.num:88", "some.other.port:1234", "10.80.88.88:88"}, c.Realms[0].KDC, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com:88", "kerberos-1.example.com:88"}, c.Realms[1].KDC, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com"}, c.Realms[1].AdminServer, "[realm] Admin_server not as expectd")

	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm[".test.gokrb5"], "Domain to realm mapping not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm["test.gokrb5"], "Domain to realm mapping not as expected")

}

func TestLoad2(t *testing.T) {
	t.Parallel()
	c, err := NewConfigFromString(krb5Conf2)
	if err != nil {
		t.Fatalf("Error loading config: %v", err)
	}

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm, "[libdefaults] default_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupRealm, "[libdefaults] dns_lookup_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupKDC, "[libdefaults] dns_lookup_kdc not as expected")
	assert.Equal(t, time.Duration(10)*time.Hour, c.LibDefaults.TicketLifetime, "[libdefaults] Ticket lifetime not as expected")
	assert.Equal(t, true, c.LibDefaults.Forwardable, "[libdefaults] forwardable not as expected")
	assert.Equal(t, "FILE:/etc/krb5.keytab", c.LibDefaults.DefaultKeytabName, "[libdefaults] default_keytab_name not as expected")
	assert.Equal(t, "FILE:/home/gokrb5/client.keytab", c.LibDefaults.DefaultClientKeytabName, "[libdefaults] default_client_keytab_name not as expected")
	assert.Equal(t, []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}, c.LibDefaults.DefaultTktEnctypes, "[libdefaults] default_tkt_enctypes not as expected")

	assert.Equal(t, 2, len(c.Realms), "Number of realms not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.Realms[0].Realm, "[realm] realm name not as expectd")
	assert.Equal(t, []string{"10.80.88.88:749"}, c.Realms[0].AdminServer, "[realm] Admin_server not as expectd")
	assert.Equal(t, []string{"10.80.88.88:464"}, c.Realms[0].KPasswdServer, "[realm] Kpasswd_server not as expectd")
	assert.Equal(t, "test.gokrb5", c.Realms[0].DefaultDomain, "[realm] Default_domain not as expectd")
	assert.Equal(t, []string{"10.80.88.88:88", "assume.port.num:88", "some.other.port:1234", "10.80.88.88:88"}, c.Realms[0].KDC, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com:88", "kerberos-1.example.com:88"}, c.Realms[1].KDC, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com"}, c.Realms[1].AdminServer, "[realm] Admin_server not as expectd")

	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm[".test.gokrb5"], "Domain to realm mapping not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm["test.gokrb5"], "Domain to realm mapping not as expected")
	assert.True(t, c.LibDefaults.NoAddresses, "No address not set as true")
}

func TestLoadNoBlankLines(t *testing.T) {
	t.Parallel()
	c, err := NewConfigFromString(krb5ConfNoBlankLines)
	if err != nil {
		t.Fatalf("Error loading config: %v", err)
	}

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm, "[libdefaults] default_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupRealm, "[libdefaults] dns_lookup_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupKDC, "[libdefaults] dns_lookup_kdc not as expected")
	assert.Equal(t, time.Duration(10)*time.Hour, c.LibDefaults.TicketLifetime, "[libdefaults] Ticket lifetime not as expected")
	assert.Equal(t, true, c.LibDefaults.Forwardable, "[libdefaults] forwardable not as expected")
	assert.Equal(t, "FILE:/etc/krb5.keytab", c.LibDefaults.DefaultKeytabName, "[libdefaults] default_keytab_name not as expected")
	assert.Equal(t, "FILE:/home/gokrb5/client.keytab", c.LibDefaults.DefaultClientKeytabName, "[libdefaults] default_client_keytab_name not as expected")
	assert.Equal(t, []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}, c.LibDefaults.DefaultTktEnctypes, "[libdefaults] default_tkt_enctypes not as expected")

	assert.Equal(t, 2, len(c.Realms), "Number of realms not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.Realms[0].Realm, "[realm] realm name not as expectd")
	assert.Equal(t, []string{"10.80.88.88:749"}, c.Realms[0].AdminServer, "[realm] Admin_server not as expectd")
	assert.Equal(t, []string{"10.80.88.88:464"}, c.Realms[0].KPasswdServer, "[realm] Kpasswd_server not as expectd")
	assert.Equal(t, "test.gokrb5", c.Realms[0].DefaultDomain, "[realm] Default_domain not as expectd")
	assert.Equal(t, []string{"10.80.88.88:88", "assume.port.num:88", "some.other.port:1234", "10.80.88.88:88"}, c.Realms[0].KDC, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com:88", "kerberos-1.example.com:88"}, c.Realms[1].KDC, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com"}, c.Realms[1].AdminServer, "[realm] Admin_server not as expectd")

	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm[".test.gokrb5"], "Domain to realm mapping not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm["test.gokrb5"], "Domain to realm mapping not as expected")

}

func TestLoadTabs(t *testing.T) {
	t.Parallel()
	cf, _ := ioutil.TempFile(os.TempDir(), "TEST-gokrb5-krb5.conf")
	defer os.Remove(cf.Name())
	cf.WriteString(krb5ConfTabs)

	c, err := Load(cf.Name())
	if err != nil {
		t.Fatalf("Error loading config: %v", err)
	}

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm, "[libdefaults] default_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupRealm, "[libdefaults] dns_lookup_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupKDC, "[libdefaults] dns_lookup_kdc not as expected")
	assert.Equal(t, time.Duration(10)*time.Hour, c.LibDefaults.TicketLifetime, "[libdefaults] Ticket lifetime not as expected")
	assert.Equal(t, true, c.LibDefaults.Forwardable, "[libdefaults] forwardable not as expected")
	assert.Equal(t, "FILE:/etc/krb5.keytab", c.LibDefaults.DefaultKeytabName, "[libdefaults] default_keytab_name not as expected")
	assert.Equal(t, "FILE:/home/gokrb5/client.keytab", c.LibDefaults.DefaultClientKeytabName, "[libdefaults] default_client_keytab_name not as expected")
	assert.Equal(t, []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}, c.LibDefaults.DefaultTktEnctypes, "[libdefaults] default_tkt_enctypes not as expected")

	assert.Equal(t, 2, len(c.Realms), "Number of realms not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.Realms[0].Realm, "[realm] realm name not as expectd")
	assert.Equal(t, []string{"10.80.88.88:749"}, c.Realms[0].AdminServer, "[realm] Admin_server not as expectd")
	assert.Equal(t, []string{"10.80.88.88:464"}, c.Realms[0].KPasswdServer, "[realm] Kpasswd_server not as expectd")
	assert.Equal(t, "test.gokrb5", c.Realms[0].DefaultDomain, "[realm] Default_domain not as expectd")
	assert.Equal(t, []string{"10.80.88.88:88", "assume.port.num:88", "some.other.port:1234", "10.80.88.88:88"}, c.Realms[0].KDC, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com:88", "kerberos-1.example.com:88"}, c.Realms[1].KDC, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com"}, c.Realms[1].AdminServer, "[realm] Admin_server not as expectd")

	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm[".test.gokrb5"], "Domain to realm mapping not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm["test.gokrb5"], "Domain to realm mapping not as expected")

}

func TestParseDuration(t *testing.T) {
	t.Parallel()
	// https://web.mit.edu/kerberos/krb5-1.12/doc/basic/date_format.html#duration
	hms, _ := time.ParseDuration("12h30m15s")
	hm, _ := time.ParseDuration("12h30m")
	h, _ := time.ParseDuration("12h")
	var tests = []struct {
		timeStr  string
		duration time.Duration
	}{
		{"100", time.Duration(100) * time.Second},
		{"12:30", hm},
		{"12:30:15", hms},
		{"1d12h30m15s", time.Duration(24)*time.Hour + hms},
		{"1d12h30m", time.Duration(24)*time.Hour + hm},
		{"1d12h", time.Duration(24)*time.Hour + h},
		{"1d", time.Duration(24) * time.Hour},
	}
	for _, test := range tests {
		d, err := parseDuration(test.timeStr)
		if err != nil {
			t.Errorf("error parsing %s: %v", test.timeStr, err)
		}
		assert.Equal(t, test.duration, d, "Duration not as expected for: "+test.timeStr)

	}

}

func TestResolveRealm(t *testing.T) {
	t.Parallel()
	c, err := NewConfigFromString(krb5Conf)
	if err != nil {
		t.Fatalf("Error loading config: %v", err)
	}

	tests := []struct {
		domainName string
		want       string
	}{
		{"unknown.com", "TEST.GOKRB5"},
		{"hostname1.example.com", "EXAMPLE.COM"},
		{"hostname2.example.com", "TEST.GOKRB5"},
		{"one.two.three.example.com", "EXAMPLE.COM"},
		{".test.gokrb5", "TEST.GOKRB5"},
		{"foo.testlowercase.org", "lowercase.org"},
	}
	for _, tt := range tests {
		t.Run(tt.domainName, func(t *testing.T) {
			if got := c.ResolveRealm(tt.domainName); got != tt.want {
				t.Errorf("config.ResolveRealm() = %v, want %v", got, tt.want)
			}
		})
	}
}
