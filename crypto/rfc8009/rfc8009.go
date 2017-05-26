package rfc8009

import (
	"crypto/hmac"
	"encoding/binary"
	"github.com/jcmturner/gokrb5/crypto/etype"
	"github.com/jcmturner/gokrb5/crypto/rfc3961"
)

func DeriveRandom(protocolKey, usage []byte, e etype.EType) ([]byte, error) {
	h := e.GetHash()()
	return KDF_HMAC_SHA2(protocolKey, []byte("prf"), usage, h.Size(), e), nil
}

func StringToKey(secret, salt, s2kparams string, e etype.EType) ([]byte, error) {
	i, err := rfc3961.S2KparamsToItertions(s2kparams)
	if err != nil {
		return nil, err
	}
	return stringToKeySHA2Iter(secret, salt, int(i), e), nil
}

func stringToKeySHA2Iter(secret, salt string, iterations int, e etype.EType) []byte {
	tkey := rfc3961.RandomToKey(rfc3961.StringToPBKDF2(secret, salt, iterations, e))
	return deriveKeyKDF_HMAC_SHA2(tkey, []byte("kerberos"), e)
}

//https://tools.ietf.org/html/rfc8009#section-3
func KDF_HMAC_SHA2(protocolKey, label, context []byte, kl int, e etype.EType) []byte {
	//k: Length in bits of the key to be outputted, expressed in big-endian binary representation in 4 bytes.
	k := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(k, uint32(kl))

	c := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(c, uint32(1))
	c = append(c, label...)
	c = append(c, byte(uint8(0)))
	if len(context) > 0 {
		c = append(c, context...)
	}
	c = append(c, k...)

	mac := hmac.New(e.GetHash(), protocolKey)
	mac.Write(c)
	return mac.Sum(nil)[:(kl / 8)]
}

func deriveKeyKDF_HMAC_SHA2(protocolKey, label []byte, e etype.EType) []byte {
	var context []byte
	return KDF_HMAC_SHA2(protocolKey, label, context, e.GetKeySeedBitLength(), e)
}
