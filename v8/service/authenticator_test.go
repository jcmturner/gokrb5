package service

import (
	"testing"

	"github.com/jcmturner/goidentity/v6"
	"github.com/stretchr/testify/assert"
)

func TestImplementsInterface(t *testing.T) {
	t.Parallel()
	//s := new(SPNEGOAuthenticator)
	var s KRB5BasicAuthenticator
	a := new(goidentity.Authenticator)
	assert.Implements(t, a, s, "SPNEGOAuthenticator type does not implement the goidentity.Authenticator interface")
}
