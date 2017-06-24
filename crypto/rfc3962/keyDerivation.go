package rfc3962

import (
	"github.com/jcmturner/gokrb5/crypto/common"
	"github.com/jcmturner/gokrb5/crypto/etype"
	"golang.org/x/crypto/pbkdf2"
)

// StringToKey returns a key derived from the string provided according to the definition in RFC 3961.
func StringToKey(secret, salt, s2kparams string, e etype.EType) ([]byte, error) {
	i, err := common.S2KparamsToItertions(s2kparams)
	if err != nil {
		return nil, err
	}
	return StringToKeyIter(secret, salt, int(i), e)
}

// StringToPBKDF2 generates an encryption key from a pass phrase and salt string using the PBKDF2 function from PKCS #5 v2.0
func StringToPBKDF2(secret, salt string, iterations int, e etype.EType) []byte {
	return pbkdf2.Key([]byte(secret), []byte(salt), iterations, e.GetKeyByteSize(), e.GetHashFunc())
}

// StringToKeyIter returns a key derived from the string provided according to the definition in RFC 3961.
func StringToKeyIter(secret, salt string, iterations int, e etype.EType) ([]byte, error) {
	tkey := e.RandomToKey(StringToPBKDF2(secret, salt, iterations, e))
	return e.DeriveKey(tkey, []byte("kerberos"))
}
