// +build integration
// To turn on this test use -tags=integration in go test command

package credentials

import (
	"fmt"
	"io"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	kinitCmd = "kinit"
	kvnoCmd  = "kvno"
)

func login() error {
	cmd := exec.Command(kinitCmd, "testuser1@TEST.GOKRB5")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("could not open stdin to %s command: %v", kinitCmd, err)
	}
	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("could not start %s command: %v", kinitCmd, err)
	}
	go func() {
		defer stdin.Close()
		io.WriteString(stdin, "passwordvalue")
	}()
	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("%s did not run successfully: %v", kinitCmd, err)
	}
	return nil
}

func getServiceTkt() error {
	cmd := exec.Command(kvnoCmd, "HTTP/host.test.gokrb5")
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

func TestLoadCCache(t *testing.T) {
	usr, _ := user.Current()
	cpath := "/tmp/krb5cc_" + usr.Uid
	c, err := LoadCCache(cpath)
	assert.Equal(t, "testuser1@TEST.GOKRB5", c.GetClientPrincipalName().GetPrincipalNameString(), "principal not as expected")
}
