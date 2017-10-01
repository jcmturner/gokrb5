// +build integration
// To turn on this test use -tags=integration in go test command

package client

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v1/config"
	"gopkg.in/jcmturner/gokrb5.v1/credentials"
	"gopkg.in/jcmturner/gokrb5.v1/iana/etypeID"
	"gopkg.in/jcmturner/gokrb5.v1/keytab"
	"gopkg.in/jcmturner/gokrb5.v1/testdata"
	"net/http"
	"testing"
)

func TestClient_SuccessfulLogin(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_SuccessfulLogin_TCPOnly(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.LibDefaults.UDPPreferenceLimit = 1
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_SuccessfulLogin_OlderKDC(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF_OLDERKDC)
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_SuccessfulLogin_ETYPE_DES3_CBC_SHA1_KD(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.LibDefaults.DefaultTktEnctypes = []string{"des3-cbc-sha1-kd"}
	c.LibDefaults.DefaultTktEnctypeIDs = []int{etypeID.DES3_CBC_SHA1_KD}
	c.LibDefaults.DefaultTGSEnctypes = []string{"des3-cbc-sha1-kd"}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int{etypeID.DES3_CBC_SHA1_KD}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_SuccessfulLogin_ETYPE_AES128_CTS_HMAC_SHA256_128(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF_LATESTKDC)
	c.LibDefaults.DefaultTktEnctypes = []string{"aes128-cts-hmac-sha256-128"}
	c.LibDefaults.DefaultTktEnctypeIDs = []int{etypeID.AES128_CTS_HMAC_SHA256_128}
	c.LibDefaults.DefaultTGSEnctypes = []string{"aes128-cts-hmac-sha256-128"}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int{etypeID.AES128_CTS_HMAC_SHA256_128}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_SuccessfulLogin_ETYPE_AES256_CTS_HMAC_SHA384_192(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF_LATESTKDC)
	c.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha384-192"}
	c.LibDefaults.DefaultTktEnctypeIDs = []int{etypeID.AES256_CTS_HMAC_SHA384_192}
	c.LibDefaults.DefaultTGSEnctypes = []string{"aes256-cts-hmac-sha384-192"}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int{etypeID.AES256_CTS_HMAC_SHA384_192}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_SuccessfulLogin_RC4HMAC(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF_AD)
	c.LibDefaults.DefaultTktEnctypes = []string{"rc4-hmac"}
	c.LibDefaults.DefaultTktEnctypeIDs = []int{etypeID.RC4_HMAC}
	c.LibDefaults.DefaultTGSEnctypes = []string{"rc4-hmac"}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int{etypeID.RC4_HMAC}
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_SuccessfulLogin_AD(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF_AD)
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_TGSExchange_EncTypes(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF_LATESTKDC)
	var tests = []string{
		"des3-cbc-sha1-kd",
		"aes128-cts-hmac-sha1-96",
		"aes256-cts-hmac-sha1-96",
		"aes128-cts-hmac-sha256-128",
		"aes256-cts-hmac-sha384-192",
		"rc4-hmac",
	}
	for _, test := range tests {
		c.LibDefaults.DefaultTktEnctypes = []string{test}
		c.LibDefaults.DefaultTktEnctypeIDs = []int{etypeID.ETypesByName[test]}
		c.LibDefaults.DefaultTGSEnctypes = []string{test}
		c.LibDefaults.DefaultTGSEnctypeIDs = []int{etypeID.ETypesByName[test]}
		cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
		cl.WithConfig(c)

		err = cl.Login()
		if err != nil {
			t.Errorf("Error on login using enctype %s: %v\n", test, err)
		}
		tkt, key, err := cl.GetServiceTicket("HTTP/host.test.gokrb5")
		if err != nil {
			t.Errorf("Error in TGS exchange using enctype %s: %v", test, err)
		}
		assert.Equal(t, "TEST.GOKRB5", tkt.Realm, "Realm in ticket not as expected for %s test", test)
		assert.Equal(t, etypeID.ETypesByName[test], key.KeyType, "Key is not for enctype %s", test)
	}
}

func TestClient_FailedLogin(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_WRONGPASSWD)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err == nil {
		t.Fatal("Login with incorrect password did not error")
	}
}

func TestClient_SuccessfulLogin_UserRequiringPreAuth(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER2_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	cl := NewClientWithKeytab("testuser2", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_SuccessfulLogin_UserRequiringPreAuth_TCPOnly(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER2_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.LibDefaults.UDPPreferenceLimit = 1
	cl := NewClientWithKeytab("testuser2", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
}

func TestClient_NetworkTimeout(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF_BAD_KDC_ADDRESS)
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err == nil {
		t.Fatal("Login with incorrect KDC address did not error")
	}
}

func TestClient_GetServiceTicket(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
	spn := "HTTP/host.test.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("Error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.GetPrincipalNameString())
	assert.Equal(t, 18, key.KeyType)

	//Check cache use - should get the same values back again
	tkt2, key2, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("Error getting service ticket: %v\n", err)
	}
	assert.Equal(t, tkt.EncPart.Cipher, tkt2.EncPart.Cipher)
	assert.Equal(t, key.KeyValue, key2.KeyValue)
}

func TestClient_GetServiceTicket_OlderKDC(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF_OLDERKDC)
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
	spn := "HTTP/host.test.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("Error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.GetPrincipalNameString())
	assert.Equal(t, 18, key.KeyType)
}

func TestClient_GetServiceTicket_AD(t *testing.T) {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF_AD)
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err = cl.Login()
	if err != nil {
		t.Fatalf("Error on login: %v\n", err)
	}
	spn := "HTTP/host.test.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("Error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.GetPrincipalNameString())
	assert.Equal(t, 18, key.KeyType)
}

func TestClient_SetSPNEGOHeader(t *testing.T) {
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("Error on AS_REQ: %v\n", err)
	}
	r, _ := http.NewRequest("GET", "http://10.80.88.88/index.html", nil)
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected")
	err = cl.SetSPNEGOHeader(r, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("Error setting client SPNEGO header: %v", err)
	}
	httpResp, err = http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")
}

func TestNewClientFromCCache(t *testing.T) {
	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatalf("Error decoding test data")
	}
	cc, err := credentials.ParseCCache(b)
	if err != nil {
		t.Fatal("Error getting test CCache")
	}
	cl, err := NewClientFromCCache(cc)
	if err != nil {
		t.Fatalf("Error creating client from CCache: %v", err)
	}
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	cl.WithConfig(c)
	if ok, err := cl.IsConfigured(); !ok {
		t.Fatalf("Client was not configured from CCache: %v", err)
	}
}
