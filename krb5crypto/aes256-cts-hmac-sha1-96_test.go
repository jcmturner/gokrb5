package krb5crypto

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAes256CtsHmacSha196_StringToPBKDF2(t *testing.T) {
	// Test vectors from RFC 3962 Appendix B
	var tests = []struct {
		iterations int
		phrase     string
		salt       string
		pbkdf2     string
	}{
		{1, "password", "ATHENA.MIT.EDUraeburn", "cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837"},
	}
	for _, test := range tests {
		var e Aes256CtsHmacSha196
		assert.Equal(t, test.pbkdf2, hex.EncodeToString(e.StringToPBKDF2(test.phrase, test.salt, test.iterations)), "PBKDF2 not as expected")
	}
}
