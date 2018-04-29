// +build integration
// To turn on this test use -tags=integration in go test command

package credentials

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v4/iana/nametype"
	"gopkg.in/jcmturner/gokrb5.v4/testdata"
	"gopkg.in/jcmturner/gokrb5.v4/types"
)

const (
	kinitCmd = "kinit"
	kvnoCmd  = "kvno"
	klistCmd = "klist"
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

func klist() (string, error) {
	cmd := exec.Command(klistCmd, "-Aef")

	stdoutR, stdoutW := io.Pipe()
	cmd.Stdout = stdoutW

	err := cmd.Start()
	if err != nil {
		return "", fmt.Errorf("could not start %s command: %v", klistCmd, err)
	}
	outBuf := new(bytes.Buffer)
	go func() {
		io.Copy(outBuf, stdoutR)
	}()

	err = cmd.Wait()
	if err != nil {
		return "", fmt.Errorf("%s did not run successfully: %v", klistCmd, err)
	}
	return string(outBuf.Bytes()), nil
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
	clist, _ := klist()
	t.Logf("OS Creds Cache contents:\n%s", clist)
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
