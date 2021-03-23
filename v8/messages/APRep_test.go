package messages

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

// Sample data from MIT Kerberos v1.19.1

// from src/tests/asn.1/ktest.h
const (
	SAMPLE_USEC       = 123456
	SAMPLE_SEQ_NUMBER = 17
	SAMPLE_NONCE      = 42
	SAMPLE_FLAGS      = 0xFEDCBA98
	SAMPLE_ERROR      = 0x3C
)

func ktest_make_sample_ap_rep_enc_part() *EncAPRepPart {
	tm, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	return &EncAPRepPart{
		CTime:          tm,
		Cusec:          SAMPLE_USEC,
		Subkey:         *ktest_make_sample_keyblock(),
		SequenceNumber: SAMPLE_SEQ_NUMBER,
	}
}

func ktest_make_sample_keyblock() *types.EncryptionKey {
	kv := []byte("12345678")
	return &types.EncryptionKey{
		KeyType:  1,
		KeyValue: kv,
	}
}

func ktest_make_sample_enc_data() *types.EncryptedData {
	return &types.EncryptedData{
		EType:  0,
		KVNO:   5,
		Cipher: []byte("krbASN.1 test message"),
	}
}

func TestUnmarshalAPRep(t *testing.T) {
	t.Parallel()
	var a APRep
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_AP_REP, a.MsgType, "MsgType is not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Ticket encPart etype not as expected")
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO, "Ticket encPart KVNO not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncPart.Cipher, "Ticket encPart cipher not as expected")
}

func TestUnmarshalEncAPRepPart(t *testing.T) {
	t.Parallel()
	var a EncAPRepPart
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep_enc_part)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, tt, a.CTime, "CTime not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, int32(1), a.Subkey.KeyType, "Subkey type not as expected")
	assert.Equal(t, []byte("12345678"), a.Subkey.KeyValue, "Subkey value not as expected")
	assert.Equal(t, int64(17), a.SequenceNumber, "Sequence number not as expected")
}

func TestUnmarshalEncAPRepPart_optionalsNULL(t *testing.T) {
	t.Parallel()
	var a EncAPRepPart
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep_enc_partOptionalsNULL)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, tt, a.CTime, "CTime not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
}

// test with all fields populated
func TestAPRepEncPartMarshall(t *testing.T) {
	t.Parallel()

	want, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep_enc_part)
	assert.Nil(t, err, "error not expected decoding test data")

	encpart := ktest_make_sample_ap_rep_enc_part()

	b, err := encpart.Marshal()
	assert.Nil(t, err, "enc part marshal error not expected")
	assert.Equal(t, want, b)
}

// test with the optionals not present
func TestAPRepEncPartMarshall_optionalsNULL(t *testing.T) {
	t.Parallel()

	want, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep_enc_partOptionalsNULL)
	assert.Nil(t, err, "error not expected decoding test data")

	encpart := ktest_make_sample_ap_rep_enc_part()
	encpart.SequenceNumber = 0
	encpart.Subkey = types.EncryptionKey{}

	b, err := encpart.Marshal()
	assert.Nil(t, err, "enc part marshal error not expected")
	assert.Equal(t, want, b)
}

func TestAprepMarshal(t *testing.T) {
	t.Parallel()

	want, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep)
	assert.Nil(t, err, "error not expected decoding test data")

	aprep := APRep{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_AP_REP,
		EncPart: *ktest_make_sample_enc_data(),
	}

	b, err := aprep.Marshal()
	assert.Nil(t, err, "enc part marshal error not expected")
	assert.Equal(t, want, b)
}
