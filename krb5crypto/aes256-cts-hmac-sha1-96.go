package krb5crypto

import (
	"errors"
)

const (

)

func StringToKey(secret string, salt string, s2kparams []byte) (protocolKey []byte) {
	return
}

func RandomToKey(b []byte) (protocolKey []byte) {
	return
}

func DeriveKey(protocolKey []byte, usage int) (specificKey []byte) {
	return
}

func Encrypt(specificKey []byte, ivec []byte, plaintext []byte) (new_ivec []byte, cyphertext []byte, err error) {
	if len(plaintext) < 1 {
		err = errors.New("Plain text is empty")
		return
	}
	return
}

func Decrypt(specificKey []byte, ivec []byte, cyphertext []byte) (new_ivec []byte, plaintext []byte, err error) {
 return
}
