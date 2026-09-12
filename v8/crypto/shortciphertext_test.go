package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

// TestDecryptMessageShortCiphertext checks that a ciphertext too short to
// contain its own checksum is rejected rather than panicking.
//
// Ciphertexts reach these functions straight from the network: an AP-REQ, a
// KRB-PRIV or a GSS-API wrap token is attacker-controlled, so a slice
// expression that assumes a minimum length is remotely reachable.
func TestDecryptMessageShortCiphertext(t *testing.T) {
	t.Parallel()
	for _, id := range []int32{
		etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA256_128,
		etypeID.AES256_CTS_HMAC_SHA384_192,
		etypeID.RC4_HMAC,
	} {
		et, err := GetEtype(id)
		if err != nil {
			t.Fatalf("etype %d: %v", id, err)
		}
		key := make([]byte, et.GetKeyByteSize())
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		k := types.EncryptionKey{KeyType: id, KeyValue: key}

		// Every length from nothing up to a full confounder plus checksum:
		// none of them is a valid message, and none of them should panic.
		max := et.GetConfounderByteSize() + et.GetHMACBitLength()/8
		for n := 0; n <= max; n++ {
			ciphertext := make([]byte, n)
			assert.NotPanics(t, func() {
				DecryptMessage(ciphertext, k, 1)
			}, "etype %d, ciphertext of %d bytes", id, n)
		}
	}
}
