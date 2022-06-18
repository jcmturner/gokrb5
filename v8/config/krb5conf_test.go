package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
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
 default_ccache_name = FILE:%{TEMP}/krb5cc.%{uid}

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
	krb5ConfJson = `{
  "LibDefaults": {
    "AllowWeakCrypto": false,
    "Canonicalize": false,
    "CCacheType": 4,
    "Clockskew": 300000000000,
    "DefaultCcacheName": "/tmp/testcc",
    "DefaultClientKeytabName": "FILE:/home/gokrb5/client.keytab",
    "DefaultKeytabName": "FILE:/etc/krb5.keytab",
    "DefaultRealm": "TEST.GOKRB5",
    "DefaultTGSEnctypes": [
      "aes256-cts-hmac-sha1-96",
      "aes128-cts-hmac-sha1-96",
      "des3-cbc-sha1",
      "arcfour-hmac-md5",
      "camellia256-cts-cmac",
      "camellia128-cts-cmac",
      "des-cbc-crc",
      "des-cbc-md5",
      "des-cbc-md4"
    ],
    "DefaultTktEnctypes": [
      "aes256-cts-hmac-sha1-96",
      "aes128-cts-hmac-sha1-96"
    ],
    "DefaultTGSEnctypeIDs": [
      18,
      17,
      23
    ],
    "DefaultTktEnctypeIDs": [
      18,
      17
    ],
    "DNSCanonicalizeHostname": true,
    "DNSLookupKDC": false,
    "DNSLookupRealm": false,
    "ExtraAddresses": null,
    "Forwardable": true,
    "IgnoreAcceptorHostname": false,
    "K5LoginAuthoritative": false,
    "K5LoginDirectory": "/home/test",
    "KDCDefaultOptions": {
      "Bytes": "AAAAEA==",
      "BitLength": 32
    },
    "KDCTimeSync": 1,
    "NoAddresses": true,
    "PermittedEnctypes": [
      "aes256-cts-hmac-sha1-96",
      "aes128-cts-hmac-sha1-96",
      "des3-cbc-sha1",
      "arcfour-hmac-md5",
      "camellia256-cts-cmac",
      "camellia128-cts-cmac",
      "des-cbc-crc",
      "des-cbc-md5",
      "des-cbc-md4"
    ],
    "PermittedEnctypeIDs": [
      18,
      17,
      23
    ],
    "PreferredPreauthTypes": [
      17,
      16,
      15,
      14
    ],
    "Proxiable": false,
    "RDNS": true,
    "RealmTryDomains": -1,
    "RenewLifetime": 0,
    "SafeChecksumType": 8,
    "TicketLifetime": 36000000000000,
    "UDPPreferenceLimit": 1465,
    "VerifyAPReqNofail": false
  },
  "Realms": [
    {
      "Realm": "TEST.GOKRB5",
      "AdminServer": [
        "10.80.88.88:749"
      ],
      "DefaultDomain": "test.gokrb5",
      "KDC": [
        "10.80.88.88:88",
        "assume.port.num:88",
        "some.other.port:1234",
        "10.80.88.88:88"
      ],
      "KPasswdServer": [
        "10.80.88.88:464"
      ],
      "MasterKDC": null
    },
    {
      "Realm": "EXAMPLE.COM",
      "AdminServer": [
        "kerberos.example.com"
      ],
      "DefaultDomain": "",
      "KDC": [
        "kerberos.example.com:88",
        "kerberos-1.example.com:88"
      ],
      "KPasswdServer": [
        "kerberos.example.com:464"
      ],
      "MasterKDC": null
    },
    {
      "Realm": "lowercase.org",
      "AdminServer": [
        "kerberos.lowercase.org"
      ],
      "DefaultDomain": "",
      "KDC": [
        "kerberos.lowercase.org:88"
      ],
      "KPasswdServer": [
        "kerberos.lowercase.org:464"
      ],
      "MasterKDC": null
    }
  ],
  "DomainRealm": {
    ".example.com": "EXAMPLE.COM",
    ".test.gokrb5": "TEST.GOKRB5",
    ".testlowercase.org": "lowercase.org",
    "hostname1.example.com": "EXAMPLE.COM",
    "hostname2.example.com": "TEST.GOKRB5",
    "test.gokrb5": "TEST.GOKRB5"
  }
}`
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

	pkg_config = `
#!/usr/bin/sh

# Copyright 2001, 2002, 2003 by the Massachusetts Institute of Technology.
# All Rights Reserved.
#

# Configurable parameters set by autoconf
version_string="Kerberos 5 release 1.18.2"

prefix=/test/usr
exec_prefix=/test/usr
includedir=/usr/include
libdir=/test/usr/lib
CC_LINK='$(CC) $(PROG_LIBPATH) $(PROG_RPATH_FLAGS) $(CFLAGS) -pie -Wl,-z,relro -Wl,-z,now $(LDFLAGS)'
KDB5_DB_LIB=
LDFLAGS='-Wl,-z,relro -Wl,--as-needed  -Wl,-z,now  '
RPATH_FLAG=''
PROG_RPATH_FLAGS=''
PTHREAD_CFLAGS='-pthread'
DL_LIB='-ldl'
DEFCCNAME='FILE:/test/tmp/krb5cc_%{uid}'
DEFKTNAME='FILE:/test/etc/krb5.keytab'
DEFCKTNAME='FILE:/test/var/kerberos/krb5/user/%{euid}/client.keytab'
SELINUX_LIBS='-lselinux '

LIBS='-lkeyutils -lcrypto  -lresolv'
GEN_LIB=

# Defaults for program
library=krb5

# Some constants
vendor_string="Massachusetts Institute of Technology"

# Process arguments
# Yes, we are sloppy, library specifications can come before options
while test $# != 0; do
	case $1 in
	--all)
		do_all=1
		;;

#### truncated for test
exit 0
`
)

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
	assert.Equal(t, fmt.Sprintf("FILE:%s/krb5cc.%d", os.TempDir(), os.Getuid()), c.LibDefaults.DefaultCcacheName, "[libdefaults] default_ccache_name not as expected")

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
	c, err := NewFromString(krb5Conf2)
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
	c, err := NewFromString(krb5ConfNoBlankLines)
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
	c, err := NewFromString(krb5Conf)
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

func TestJSON(t *testing.T) {
	t.Parallel()
	c, err := NewFromString(krb5Conf)
	if err != nil {
		t.Fatalf("Error loading config: %v", err)
	}
	c.LibDefaults.K5LoginDirectory = "/home/test"
	c.LibDefaults.DefaultCcacheName = "/tmp/testcc"
	j, err := c.JSON()
	if err != nil {
		t.Errorf("error marshaling krb config to JSON: %v", err)
	}
	assert.Equal(t, krb5ConfJson, j, "krb config marshaled json not as expected")

	t.Log(j)
}

func TestPkgConfigVars(t *testing.T) {
	t.Parallel()

	fh, err := ioutil.TempFile("", "test")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}

	defer os.Remove(fh.Name())

	if _, err := fh.Write([]byte(pkg_config)); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	fh.Sync()

	fname := fh.Name()
	vars := PkgConfigVars(&fname)
	assert.Equal(t, "/test/usr", vars["prefix"])
	assert.Equal(t, "/test/usr", vars["exec_prefix"])
	assert.Equal(t, "/usr/include", vars["includedir"])
	assert.Equal(t, "/test/usr/lib", vars["libdir"])
	assert.Equal(t, "FILE:/test/tmp/krb5cc_%{uid}", vars["DEFCCNAME"])
	assert.Equal(t, "FILE:/test/etc/krb5.keytab", vars["DEFKTNAME"])
	assert.Equal(t, "FILE:/test/var/kerberos/krb5/user/%{euid}/client.keytab", vars["DEFCKTNAME"])
}

func TestExpandParams(t *testing.T) {
	t.Parallel()

	vars := PkgConfigVars(nil)

	want := fmt.Sprintf("FILE:/tmp/krb5cc_%d", os.Getuid())
	assert.Equal(t, want, ExpandParams("FILE:/tmp/krb5cc_%{uid}"))

	want = fmt.Sprintf("test %s", vars["libdir"])
	assert.Equal(t, want, ExpandParams("test %{LIBDIR}"))

	want = fmt.Sprintf("%s/user-%d", os.TempDir(), os.Getuid())
	assert.Equal(t, want, ExpandParams("%{TEMP}/user-%{uid}"))
}
