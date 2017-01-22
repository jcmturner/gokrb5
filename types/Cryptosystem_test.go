package types

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"github.com/jcmturner/gokrb5/testdata"
	"testing"
)


func TestUnmarshalEncryptedData(t *testing.T) {
	var a EncryptedData
	v := "encode_krb5_enc_data"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, testdata.TEST_ETYPE, a.EType, "Encrypted data Etype not as expected")
	assert.Equal(t, testdata.TEST_KVNO, a.KVNO, "Encrypted data KVNO not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.Cipher, "Ecrypted data ciphertext not as expected")
}

func TestUnmarshalEncryptionKey(t *testing.T) {
	var a EncryptionKey
	v := "encode_krb5_keyblock"
	b, err := hex.DecodeString(testdata.TestVectors[v])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", v, err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", v, err)
	}
	assert.Equal(t, 1, a.KeyType, "Key type not as expected")
	assert.Equal(t, []byte("12345678"), a.KeyValue, "Key value not as expected")
}
