package gssapi

import (
	"encoding/hex"
	"testing"

	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

const (
	kerberosTokenV1        = "603006092a864886f71201020202011100ffffffffec07ef3418bb9d5384c646f1ce946db60c901a9dedf79ea30101000001"
	replyToKerberosTokenV1 = "603006092a864886f71201020202011100ffffffff3085bf00a417fcf490f1c33c80eee85253734436d6f1048a0101000001"

	sessionKeyTypeV1       = 23
	sessionKeyV1           = "c5b294ffa21a9cb1050a13213a88cd7b"

	checksum  = "7ba2b10519ffdc23"
	sndSeqNum = "bbea237800000000"
)

func getSessionKeyV1(sessionKey string, keyType int32) types.EncryptionKey {
	key, _ := hex.DecodeString(sessionKey)
	return types.EncryptionKey{
		KeyType:  keyType,
		KeyValue: key,
	}
}

func TestUnmarshal_KerberosTokenV1(t *testing.T) {
	kerToken, _ := hex.DecodeString(kerberosTokenV1)

	expectedWrapTokenV1 := WrapTokenV1 {}
	expectedWrapTokenV1.SGN_ALG    = kerToken[15:17]
	expectedWrapTokenV1.SEAL_ALG   = kerToken[17:19]
	expectedWrapTokenV1.SndSeqNum  = kerToken[21:29]
	expectedWrapTokenV1.CheckSum   = kerToken[29:37]
	expectedWrapTokenV1.Confounder = kerToken[37:45]
	expectedWrapTokenV1.Payload    = kerToken[45:]

	var wt WrapTokenV1
	err := wt.Unmarshal(kerToken, false)

	assert.Nil(t, err, "Unexpected error occurred.")
	assert.Equal(t, &expectedWrapTokenV1, &wt, "Token not decoded as expected.")
}

func TestVerify_KerberosTokenV1(t *testing.T) {
	kerToken, _ := hex.DecodeString(kerberosTokenV1)

	var wt WrapTokenV1
	err := wt.Unmarshal(kerToken, false)
	assert.Nil(t, err, "Unexpected error occurred.")

	success, err := wt.Verify(getSessionKeyV1(sessionKeyV1, sessionKeyTypeV1), acceptorSign)
	assert.Nil(t, err, "Unexpected error occurred.")
	assert.Equal(t, true, success, "Token not decoded as expected.")
}

// ========================
func TestUnmarshal_ReplyToKerberosTokenV1(t *testing.T) {
	kerToken, _ := hex.DecodeString(replyToKerberosTokenV1)

	expectedWrapTokenV1 := WrapTokenV1 {}
	expectedWrapTokenV1.SGN_ALG    = kerToken[15:17]
	expectedWrapTokenV1.SEAL_ALG   = kerToken[17:19]
	expectedWrapTokenV1.SndSeqNum  = kerToken[21:29]
	expectedWrapTokenV1.CheckSum   = kerToken[29:37]
	expectedWrapTokenV1.Confounder = kerToken[37:45]
	expectedWrapTokenV1.Payload    = kerToken[45:]

	var wt WrapTokenV1
	err := wt.Unmarshal(kerToken, false)

	assert.Nil(t, err, "Unexpected error occurred.")
	assert.Equal(t, &expectedWrapTokenV1, &wt, "Token not decoded as expected.")
}

func TestVerify_ReplyToKerberosTokenV1(t *testing.T) {
	kerToken, _ := hex.DecodeString(replyToKerberosTokenV1)

	var wt WrapTokenV1
	err := wt.Unmarshal(kerToken, false)
	assert.Nil(t, err, "Unexpected error occurred.")

	success, err := wt.Verify(getSessionKeyV1(sessionKeyV1, sessionKeyTypeV1), acceptorSign)
	assert.Nil(t, err, "Unexpected error occurred.")
	assert.Equal(t, true, success, "Token not decoded as expected.")
}

// ========================
func TestEncodeDecodeSndSeqNum(t *testing.T) {
	session, _ := hex.DecodeString(sessionKeyV1)
	check, _   := hex.DecodeString(checksum)
	ssn, _     := hex.DecodeString(sndSeqNum)

	expectedSndSeqNum := []byte{0x93, 0x4b, 0x9a, 0x21, 0xc8, 0x23, 0xf8, 0x98}

	wrapTokenV1           := WrapTokenV1 {}
	wrapTokenV1.SndSeqNum  = ssn

	wrapTokenV1.encryptSndSeqNum(session, check)

	assert.Equal(t, expectedSndSeqNum, wrapTokenV1.SndSeqNum, "SndSeqNum is not correctly encrypted")
}
