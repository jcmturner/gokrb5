// +build integration
// To turn on this test use -tags=integration in go test command

package client

import (
	"encoding/hex"
	"github.com/jcmturner/gokrb5/config"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/testdata"
	"github.com/stretchr/testify/assert"
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
	c.LibDefaults.Udp_preference_limit = 1
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
	c.LibDefaults.Udp_preference_limit = 1
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
	r, _ := http.NewRequest("GET", "http://10.80.88.90/index.html", nil)
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
