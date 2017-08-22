package credentials

import (
	"github.com/jcmturner/goidentity"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestImplementsInterface(t *testing.T) {
	u := new(Credentials)
	i := new(goidentity.Identity)
	assert.Implements(t, i, u, "Credentials type does not implement the Identity interface")
}
