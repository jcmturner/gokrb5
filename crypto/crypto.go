// Cryptographic packages for Kerberos 5 implementation.
package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/crypto/aes"
	"github.com/jcmturner/gokrb5/crypto/engine"
	"github.com/jcmturner/gokrb5/crypto/etype"
	"github.com/jcmturner/gokrb5/iana/chksumtype"
	"github.com/jcmturner/gokrb5/iana/etypeID"
	"github.com/jcmturner/gokrb5/iana/patype"
	"github.com/jcmturner/gokrb5/types"
)

func GetEtype(id int) (etype.EType, error) {
	switch id {
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		var et aes.Aes128CtsHmacSha96
		return et, nil
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		var et aes.Aes256CtsHmacSha96
		return et, nil
	default:
		return nil, fmt.Errorf("Unknown or unsupported EType: %d", id)
	}
}

func GetChksumEtype(id int) (etype.EType, error) {
	switch id {
	case chksumtype.HMAC_SHA1_96_AES128:
		var et aes.Aes128CtsHmacSha96
		return et, nil
	case chksumtype.HMAC_SHA1_96_AES256:
		var et aes.Aes256CtsHmacSha96
		return et, nil
	default:
		return nil, fmt.Errorf("Unknown or unsupported checksum type: %d", id)
	}
}

func GetKeyFromPassword(passwd string, cname types.PrincipalName, realm string, etypeID int, pas types.PADataSequence) (types.EncryptionKey, etype.EType, error) {
	var key types.EncryptionKey
	et, err := GetEtype(etypeID)
	if err != nil {
		return key, et, fmt.Errorf("Error getting encryption type: %v", err)
	}
	sk2p := et.GetDefaultStringToKeyParams()
	var salt string
	var paID int
	for _, pa := range pas {
		switch pa.PADataType {
		case patype.PA_PW_SALT:
			if paID > pa.PADataType {
				continue
			}
			salt = string(pa.PADataValue)
		case patype.PA_ETYPE_INFO:
			if paID > pa.PADataType {
				continue
			}
			var eti types.ETypeInfo
			err := eti.Unmarshal(pa.PADataValue)
			if err != nil {
				return key, et, fmt.Errorf("Error unmashalling PA Data to PA-ETYPE-INFO2: %v", err)
			}
			if etypeID != eti[0].EType {
				et, err = GetEtype(eti[0].EType)
				if err != nil {
					return key, et, fmt.Errorf("Error getting encryption type: %v", err)
				}
			}
			salt = string(eti[0].Salt)
		case patype.PA_ETYPE_INFO2:
			if paID > pa.PADataType {
				continue
			}
			var et2 types.ETypeInfo2
			err := et2.Unmarshal(pa.PADataValue)
			if err != nil {
				return key, et, fmt.Errorf("Error unmashalling PA Data to PA-ETYPE-INFO2: %v", err)
			}
			if etypeID != et2[0].EType {
				et, err = GetEtype(et2[0].EType)
				if err != nil {
					return key, et, fmt.Errorf("Error getting encryption type: %v", err)
				}
			}
			if len(et2[0].S2KParams) == 4 {
				sk2p = hex.EncodeToString(et2[0].S2KParams)
			}
			salt = et2[0].Salt
		}
	}
	if salt == "" {
		salt = cname.GetSalt(realm)
	}
	k, err := et.StringToKey(passwd, salt, sk2p)
	if err != nil {
		return key, et, fmt.Errorf("Error deriving key from string: %+v", err)
	}
	key = types.EncryptionKey{
		KeyType:  etypeID,
		KeyValue: k,
	}
	return key, et, nil
}

// Pass a usage value of zero to use the key provided directly rather than deriving one
func GetEncryptedData(plainBytes []byte, key types.EncryptionKey, usage uint32, kvno int) (types.EncryptedData, error) {
	var ed types.EncryptedData
	et, err := GetEtype(key.KeyType)
	if err != nil {
		return ed, fmt.Errorf("Error getting etype: %v", err)
	}
	k := key.KeyValue
	if usage != 0 {
		k, err = et.DeriveKey(key.KeyValue, engine.GetUsageKe(uint32(usage)))
		if err != nil {
			return ed, fmt.Errorf("Error deriving key: %v", err)
		}
	}
	//confounder
	c := make([]byte, et.GetConfounderByteSize())
	_, err = rand.Read(c)
	if err != nil {
		return ed, fmt.Errorf("Could not generate random confounder: %v", err)
	}
	plainBytes = append(c, plainBytes...)
	_, b, err := et.Encrypt(k, plainBytes)
	if err != nil {
		return ed, fmt.Errorf("Error encrypting data: %v", err)
	}
	ih, err := engine.GetIntegrityHash(plainBytes, key.KeyValue, usage, et)
	b = append(b, ih...)
	ed = types.EncryptedData{
		EType:  key.KeyType,
		Cipher: b,
		KVNO:   kvno,
	}
	return ed, nil
}

func DecryptEncPart(ed types.EncryptedData, key types.EncryptionKey, usage uint32) ([]byte, error) {
	//Derive the key
	et, err := GetEtype(key.KeyType)
	k, err := et.DeriveKey(key.KeyValue, engine.GetUsageKe(usage))
	if err != nil {
		return nil, fmt.Errorf("Error deriving key: %v", err)
	}
	// Strip off the checksum from the end
	b, err := et.Decrypt(k, ed.Cipher[:len(ed.Cipher)-et.GetHMACBitLength()/8])
	if err != nil {
		return nil, fmt.Errorf("Error decrypting: %v", err)
	}
	//Verify checksum
	if !et.VerifyIntegrity(key.KeyValue, ed.Cipher, b, usage) {
		return nil, errors.New("Error decrypting encrypted part: integrity verification failed")
	}
	//Remove the confounder bytes
	b = b[et.GetConfounderByteSize():]
	if err != nil {
		return nil, fmt.Errorf("Error decrypting encrypted part: %v", err)
	}
	return b, nil
}
