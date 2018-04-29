// +build integration
// To turn on this test use -tags=integration in go test command

package credentials

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v4/client"
	"gopkg.in/jcmturner/gokrb5.v4/config"
	"gopkg.in/jcmturner/gokrb5.v4/iana/nametype"
	"gopkg.in/jcmturner/gokrb5.v4/testdata"
	"gopkg.in/jcmturner/gokrb5.v4/types"
)

const (
	kinitCmd = "kinit"
	kvnoCmd  = "kvno"
	spn      = "HTTP/host.test.gokrb5"
)

func login() error {
	file, err := os.Create("/etc/krb5.conf")
	if err != nil {
		return fmt.Errorf("cannot open krb5.conf: %v", err)
	}
	defer file.Close()
	fmt.Fprintf(file, testdata.TEST_KRB5CONF)

	cmd := exec.Command(kinitCmd, "testuser1@TEST.GOKRB5")

	stdinR, stdinW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	cmd.Stdin = stdinR
	cmd.Stderr = stderrW

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("could not start %s command: %v", kinitCmd, err)
	}

	go func() {
		io.WriteString(stdinW, "passwordvalue")
		stdinW.Close()
	}()
	errBuf := new(bytes.Buffer)
	go func() {
		io.Copy(errBuf, stderrR)
		stderrR.Close()
	}()

	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("%s did not run successfully: %v stderr: %s", kinitCmd, err, string(errBuf.Bytes()))
	}
	return nil
}

func getServiceTkt() error {
	cmd := exec.Command(kvnoCmd, spn)
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("could not start %s command: %v", kvnoCmd, err)
	}
	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("%s did not run successfully: %v", kvnoCmd, err)
	}
	return nil
}

func loadCCache() (CCache, error) {
	usr, _ := user.Current()
	cpath := "/tmp/krb5cc_" + usr.Uid
	return LoadCCache(cpath)
}

func TestLoadCCache(t *testing.T) {
	err := login()
	if err != nil {
		t.Fatalf("error logging in with kinit: %v", err)
	}
	c, err := loadCCache()
	if err != nil {
		t.Errorf("error loading CCache: %v", err)
	}
	pn := c.GetClientPrincipalName()
	assert.Equal(t, "testuser1", pn.GetPrincipalNameString(), "principal not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.GetClientRealm(), "realm not as expected")
}

func TestCCacheEntries(t *testing.T) {
	err := login()
	if err != nil {
		t.Fatalf("error logging in with kinit: %v", err)
	}
	err = getServiceTkt()
	if err != nil {
		t.Fatalf("error getting service ticket: %v", err)
	}
	c, err := loadCCache()
	if err != nil {
		t.Errorf("error loading CCache: %v", err)
	}
	creds := c.GetEntries()
	var found bool
	n := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, spn)
	for _, cred := range creds {
		if cred.Server.PrincipalName.Equal(n) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Entry for %s not found in CCache", spn)
	}
}

func TestGetServiceTicketFromCCacheTGT(t *testing.T) {
	err := login()
	if err != nil {
		t.Fatalf("error logging in with kinit: %v", err)
	}
	c, err := loadCCache()
	if err != nil {
		t.Errorf("error loading CCache: %v", err)
	}
	cfg, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	cl, err := client.NewClientFromCCache(c)
	if err != nil {
		t.Fatalf("error generating client from ccache: %v", err)
	}
	cl.WithConfig(cfg)
	url := os.Getenv("TEST_HTTP_URL")
	if url == "" {
		url = testdata.TEST_HTTP_URL
	}
	r, _ := http.NewRequest("GET", url, nil)
	err = cl.SetSPNEGOHeader(r, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client SPNEGO header: %v", err)
	}
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "status code in response to client SPNEGO request not as expected")
}
