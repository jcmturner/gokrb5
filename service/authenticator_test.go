package service

import (
	"github.com/jcmturner/goidentity"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestImplementsInterface(t *testing.T) {
	//s := new(SPNEGOAuthenticator)
	var s SPNEGOAuthenticator
	a := new(goidentity.Authenticator)
	assert.Implements(t, a, s, "SPNEGOAuthenticator type does not implement the goidentity.Authenticator interface")
}
