package types

import (
	"github.com/jcmturner/asn1"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestKerberosFlags_SetFlag(t *testing.T) {
	b := []byte{byte(64), byte(0), byte(0), byte(16)}
	var f asn1.BitString
	SetFlag(&f, Forwardable)
	SetFlag(&f, RenewableOK)
	assert.Equal(t, b, f.Bytes, "Flag bytes not as expected")
}

func TestKerberosFlags_UnsetFlag(t *testing.T) {
	b := []byte{byte(64), byte(0), byte(0), byte(0)}
	var f asn1.BitString
	SetFlag(&f, Forwardable)
	SetFlag(&f, RenewableOK)
	UnsetFlag(&f, RenewableOK)
	assert.Equal(t, b, f.Bytes, "Flag bytes not as expected")
}

func TestKerberosFlags_IsFlagSet(t *testing.T) {
	var f asn1.BitString
	SetFlag(&f, Forwardable)
	SetFlag(&f, RenewableOK)
	UnsetFlag(&f, Proxiable)
	assert.True(t, IsFlagSet(&f, Forwardable))
	assert.True(t, IsFlagSet(&f, RenewableOK))
	assert.False(t, IsFlagSet(&f, Proxiable))
}
