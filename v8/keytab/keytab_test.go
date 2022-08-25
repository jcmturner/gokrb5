package keytab

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshal(t *testing.T) {
	t.Parallel()
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := New()
	err := kt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error parsing keytab data: %v\n", err)
	}
	assert.Equal(t, uint8(2), kt.version, "Keytab version not as expected")
	assert.Equal(t, uint32(1), kt.Entries[0].KVNO, "KVNO not as expected")
	assert.Equal(t, uint8(1), kt.Entries[0].KVNO8, "KVNO8 not as expected")
	assert.Equal(t, time.Unix(1505669592, 0), kt.Entries[0].Timestamp, "Timestamp not as expected")
	assert.Equal(t, int32(17), kt.Entries[0].Key.KeyType, "Key's EType not as expected")
	assert.Equal(t, "698c4df8e9f60e7eea5a21bf4526ad25", hex.EncodeToString(kt.Entries[0].Key.KeyValue), "Key material not as expected")
	assert.Equal(t, int16(1), kt.Entries[0].Principal.NumComponents, "Number of components in principal not as expected")
	assert.Equal(t, int32(1), kt.Entries[0].Principal.NameType, "Name type of principal not as expected")
	assert.Equal(t, "TEST.GOKRB5", kt.Entries[0].Principal.Realm, "Realm of principal not as expected")
	assert.Equal(t, "testuser1", kt.Entries[0].Principal.Components[0], "Component in principal not as expected")
}

func TestMarshal(t *testing.T) {
	t.Parallel()
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := New()
	err := kt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error parsing keytab data: %v\n", err)
	}
	mb, err := kt.Marshal()
	if err != nil {
		t.Fatalf("Error marshaling: %v", err)
	}
	assert.Equal(t, b, mb, "Marshaled bytes not the same as input bytes")
	err = kt.Unmarshal(mb)
	if err != nil {
		t.Fatalf("Error parsing marshaled bytes: %v", err)
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	f := "test/testdata/testuser1.testtab"
	cwd, _ := os.Getwd()
	dir := os.Getenv("TRAVIS_BUILD_DIR")
	if dir != "" {
		f = dir + "/" + f
	} else if filepath.Base(cwd) == "keytab" {
		f = "../" + f
	}
	kt, err := Load(f)
	if err != nil {
		t.Fatalf("could not load keytab: %v", err)
	}
	assert.Equal(t, uint8(2), kt.version, "keytab version not as expected")
	assert.Equal(t, 12, len(kt.Entries), "keytab entry count not as expected: %+v", *kt)
	for _, e := range kt.Entries {
		if e.Principal.Realm != "TEST.GOKRB5" {
			t.Error("principal realm not as expected")
		}
		if e.Principal.NameType != int32(1) {
			t.Error("name type not as expected")
		}
		if e.Principal.NumComponents != int16(1) {
			t.Error("number of component not as expected")
		}
		if len(e.Principal.Components) != 1 {
			t.Error("number of component not as expected")
		}
		if e.Principal.Components[0] != "testuser1" {
			t.Error("principal components not as expected")
		}
		if e.Timestamp.IsZero() {
			t.Error("entry timestamp incorrect")
		}
		if e.KVNO == uint32(0) {
			t.Error("entry kvno not as expected")
		}
		if e.KVNO8 == uint8(0) {
			t.Error("entry kvno8 not as expected")
		}
	}
}

// This test provides inputs to readBytes that previously
// caused a panic.
func TestReadBytes(t *testing.T) {
	var endian binary.ByteOrder
	endian = binary.BigEndian
	p := 0

	if _, err := readBytes(nil, &p, 1, &endian); err == nil {
		t.Fatal("err should be populated because s was given that exceeds array length")
	}
	if _, err := readBytes(nil, &p, -1, &endian); err == nil {
		t.Fatal("err should be given because negative s was given")
	}
}

func TestUnmarshalPotentialPanics(t *testing.T) {
	kt := New()

	// Test a good keytab with bad bytes to unmarshal. These should
	// return errors, but not panic.
	if err := kt.Unmarshal(nil); err == nil {
		t.Fatal("should have errored, input is absent")
	}
	if err := kt.Unmarshal([]byte{}); err == nil {
		t.Fatal("should have errored, input is empty")
	}
	// Incorrect first byte.
	if err := kt.Unmarshal([]byte{4}); err == nil {
		t.Fatal("should have errored, input isn't long enough")
	}
	// First byte, but no further content.
	if err := kt.Unmarshal([]byte{5}); err == nil {
		t.Fatal("should have errored, input isn't long enough")
	}
}

// cxf testing stuff
func TestBadKeytabs(t *testing.T) {
	badPayloads := make([]string, 3)
	badPayloads = append(badPayloads, "BQIwMDAwMDA=")
	badPayloads = append(badPayloads, "BQIAAAAwAAEACjAwMDAwMDAwMDAAIDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw")
	badPayloads = append(badPayloads, "BQKAAAAA")
	for _, v := range badPayloads {
		decodedKt, _ := base64.StdEncoding.DecodeString(v)
		parsedKt := new(Keytab)
		parsedKt.Unmarshal(decodedKt)
	}
}

func TestKeytabEntriesUser(t *testing.T) {

	// Load known-good keytab generated with ktutil
	ktutilb64 := "BQIAAABGAAEAC0VYQU1QTEUuT1JHAAR1c2VyAAAAAV5ePQAfABIAIG6I6ys5Me8XyS54Ck7kIfFBH/WxBOP3W1DdE/ntBPnGAAAAHwAAADYAAQALRVhBTVBMRS5PUkcABHVzZXIAAAABXl49AB8AEQAQm7fVug9VRBJVhEGjHyN3EgAAAB8AAAA2AAEAC0VYQU1QTEUuT1JHAAR1c2VyAAAAAV5ePQAfABcAEBENDFHhRNNvt+T54BL7uIgAAAAf"
	ktutilbytes, err := base64.StdEncoding.DecodeString(ktutilb64)
	if err != nil {
		t.Errorf("Could not parse b64 ktutil keytab: %s", err)
	}
	ktutil := new(Keytab)
	err = ktutil.Unmarshal(ktutilbytes)
	if err != nil {
		t.Fatalf("Could not load ktutil-generated keytab: %s", err)
	}

	// Generate the same keytab with gokrb5
	var ts time.Time = ktutil.Entries[0].Timestamp
	var encTypes []int32 = []int32{
		etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.RC4_HMAC,
	}

	kt := New()
	for _, et := range encTypes {
		err = kt.AddEntry("user", "EXAMPLE.ORG", "hello123", ts, uint8(31), et)
		if err != nil {
			t.Errorf("Error adding entry to keytab: %s", err)
		}
	}
	generated, err := kt.Marshal()
	if err != nil {
		t.Errorf("Error marshalling generated keytab: %s", err)
	}

	// Compare content
	assert.Equal(t, generated, ktutilbytes, "Service keytab doesn't match ktutil keytab")
}

func TestKeytabEntriesService(t *testing.T) {

	// Load known-good keytab generated with ktutil
	ktutilb64 := "BQIAAABXAAIAC0VYQU1QTEUuT1JHAARIVFRQAA93d3cuZXhhbXBsZS5vcmcAAAABXl49ggoAEgAgOCSpM5CdiZQn1+rUtLtt6sTrg5Saw1DXJMai7vDWJ0QAAAAKAAAARwACAAtFWEFNUExFLk9SRwAESFRUUAAPd3d3LmV4YW1wbGUub3JnAAAAAV5ePYIKABEAEDpczoDyER1jscz0RWkThCMAAAAKAAAARwACAAtFWEFNUExFLk9SRwAESFRUUAAPd3d3LmV4YW1wbGUub3JnAAAAAV5ePYIKABcAELP27YfH0Th5rD+GtJkQmXQAAAAK"
	ktutilbytes, err := base64.StdEncoding.DecodeString(ktutilb64)
	if err != nil {
		t.Errorf("Could not parse b64 ktutil keytab: %s", err)
	}
	ktutil := new(Keytab)
	err = ktutil.Unmarshal(ktutilbytes)
	if err != nil {
		t.Errorf("Could not load ktutil-generated keytab: %s", err)
	}

	// Generate the same keytab with gokrb5
	var ts time.Time = ktutil.Entries[0].Timestamp
	var encTypes []int32 = []int32{
		etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.RC4_HMAC,
	}

	kt := New()
	for _, et := range encTypes {
		err = kt.AddEntry("HTTP/www.example.org", "EXAMPLE.ORG", "hello456", ts, uint8(10), et)
		if err != nil {
			t.Errorf("Error adding entry to keytab: %s", err)
		}
	}
	generated, err := kt.Marshal()
	if err != nil {
		t.Errorf("Error marshalling generated keytab: %s", err)
	}

	// Compare content
	assert.Equal(t, generated, ktutilbytes, "Service keytab doesn't match ktutil keytab")
}

func TestKeytabEntriesComputer(t *testing.T) {
	// Load known-good keytab generated with ktutil
	ktutilb64 := string(`BQIAAABAAAEAC0NZTE9OLkxPQ0FMAA5sb3NwZWNuaW5mcmEzJAAAAAFjB6XsBQAXABARDQxR4UTT
b7fk+eAS+7iIAAAABQAAAEAAAQALQ1lMT04uTE9DQUwADmxvc3BlY25pbmZyYTMkAAAAAWMHpewF
ABEAEDgTr5D44EdeyfbxcTNpiO4AAAAFAAAAUAABAAtDWUxPTi5MT0NBTAAObG9zcGVjbmluZnJh
MyQAAAABYwel7AUAEgAg9LXbCPYwoqorwz7TJIe3TIMRyiR7u5J4trLwtXgAzBMAAAAFAAAAQAAB
AAtDWUxPTi5MT0NBTAAOTE9TUEVDTklORlJBMyQAAAABYwel7AUAFwAQEQ0MUeFE02+35PngEvu4
iAAAAAUAAABAAAEAC0NZTE9OLkxPQ0FMAA5MT1NQRUNOSU5GUkEzJAAAAAFjB6XsBQARABA4E6+Q
+OBHXsn28XEzaYjuAAAABQAAAFAAAQALQ1lMT04uTE9DQUwADkxPU1BFQ05JTkZSQTMkAAAAAWMH
pewFABIAIPS12wj2MKKqK8M+0ySHt0yDEcoke7uSeLay8LV4AMwTAAAABQAAAFUAAgALQ1lMT04u
TE9DQUwABGhvc3QAHWxvc3BlY25pbmZyYTMuZWNuLmN5bG9uLmxvY2FsAAAAAWMHpewFABcAEBEN
DFHhRNNvt+T54BL7uIgAAAAFAAAAVQACAAtDWUxPTi5MT0NBTAAEaG9zdAAdbG9zcGVjbmluZnJh
My5lY24uY3lsb24ubG9jYWwAAAABYwel7AUAEQAQOBOvkPjgR17J9vFxM2mI7gAAAAUAAABlAAIA
C0NZTE9OLkxPQ0FMAARob3N0AB1sb3NwZWNuaW5mcmEzLmVjbi5jeWxvbi5sb2NhbAAAAAFjB6Xs
BQASACD0tdsI9jCiqivDPtMkh7dMgxHKJHu7kni2svC1eADMEwAAAAUAAABFAAIAC0NZTE9OLkxP
Q0FMAARob3N0AA1sb3NwZWNuaW5mcmEzAAAAAWMHpewFABcAEBENDFHhRNNvt+T54BL7uIgAAAAF
AAAARQACAAtDWUxPTi5MT0NBTAAEaG9zdAANbG9zcGVjbmluZnJhMwAAAAFjB6XsBQARABA4E6+Q
+OBHXsn28XEzaYjuAAAABQAAAFUAAgALQ1lMT04uTE9DQUwABGhvc3QADWxvc3BlY25pbmZyYTMA
AAABYwel7AUAEgAg9LXbCPYwoqorwz7TJIe3TIMRyiR7u5J4trLwtXgAzBMAAAAFAAAAYgACAAtD
WUxPTi5MT0NBTAARUmVzdHJpY3RlZEtyYkhvc3QAHWxvc3BlY25pbmZyYTMuZWNuLmN5bG9uLmxv
Y2FsAAAAAWMHpewFABcAEBENDFHhRNNvt+T54BL7uIgAAAAFAAAAYgACAAtDWUxPTi5MT0NBTAAR
UmVzdHJpY3RlZEtyYkhvc3QAHWxvc3BlY25pbmZyYTMuZWNuLmN5bG9uLmxvY2FsAAAAAWMHpewF
ABEAEDgTr5D44EdeyfbxcTNpiO4AAAAFAAAAcgACAAtDWUxPTi5MT0NBTAARUmVzdHJpY3RlZEty
Ykhvc3QAHWxvc3BlY25pbmZyYTMuZWNuLmN5bG9uLmxvY2FsAAAAAWMHpewFABIAIPS12wj2MKKq
K8M+0ySHt0yDEcoke7uSeLay8LV4AMwTAAAABQAAAFIAAgALQ1lMT04uTE9DQUwAEVJlc3RyaWN0
ZWRLcmJIb3N0AA1MT1NQRUNOSU5GUkEzAAAAAWMHpewFABcAEBENDFHhRNNvt+T54BL7uIgAAAAF
AAAAUgACAAtDWUxPTi5MT0NBTAARUmVzdHJpY3RlZEtyYkhvc3QADUxPU1BFQ05JTkZSQTMAAAAB
Ywel7AUAEQAQOBOvkPjgR17J9vFxM2mI7gAAAAUAAABiAAIAC0NZTE9OLkxPQ0FMABFSZXN0cmlj
dGVkS3JiSG9zdAANTE9TUEVDTklORlJBMwAAAAFjB6XsBQASACD0tdsI9jCiqivDPtMkh7dMgxHK
JHu7kni2svC1eADMEwAAAAUAAABFAAIAC0NZTE9OLkxPQ0FMAARob3N0AA1MT1NQRUNOSU5GUkEz
AAAAAWMHpewFABcAEBENDFHhRNNvt+T54BL7uIgAAAAFAAAARQACAAtDWUxPTi5MT0NBTAAEaG9z
dAANTE9TUEVDTklORlJBMwAAAAFjB6XsBQARABA4E6+Q+OBHXsn28XEzaYjuAAAABQAAAFUAAgAL
Q1lMT04uTE9DQUwABGhvc3QADUxPU1BFQ05JTkZSQTMAAAABYwel7AUAEgAg9LXbCPYwoqorwz7T
JIe3TIMRyiR7u5J4trLwtXgAzBMAAAAF`)
	ktutilbytes, err := base64.StdEncoding.DecodeString(ktutilb64)
	if err != nil {
		t.Errorf("Could not parse b64 ktutil keytab: %s", err)
	}
	ktutil := new(Keytab)
	err = ktutil.Unmarshal(ktutilbytes)
	if err != nil {
		t.Fatalf("Could not load ktutil-generated keytab: %s", err)
	}

	// Generate the same keytab with gokrb5
	ts := ktutil.Entries[0].Timestamp
	var encTypes = []int32{
		etypeID.RC4_HMAC,
		etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.AES256_CTS_HMAC_SHA1_96,
	}

	principals := []string{
		"lospecninfra3$",
		"LOSPECNINFRA3$",
		"host/lospecninfra3.ecn.cylon.local",
		"host/lospecninfra3",
		"RestrictedKrbHost/lospecninfra3.ecn.cylon.local",
		"RestrictedKrbHost/LOSPECNINFRA3",
		"host/LOSPECNINFRA3",
	}

	kt := New()
	for _, princ := range principals {
		for _, et := range encTypes {
			err = kt.AddActiveDirectoryComputerAccountEntry(princ, "CYLON.LOCAL", "hello123", "lospecninfra3", ts, uint8(5), et)
			if err != nil {
				t.Errorf("Error adding entry to keytab: %s", err)
			}
		}
	}
	generated, err := kt.Marshal()
	if err != nil {
		t.Errorf("Error marshalling generated keytab: %s", err)
	}

	// Compare content
	assert.Equal(t, generated, ktutilbytes, "Computer keytab doesn't match ktutil keytab")
}

func TestKeytab_GetEncryptionKey(t *testing.T) {
	princ := "HTTP/princ.test.gokrb5"
	realm := "TEST.GOKRB5"

	kt := New()
	kt.AddEntry(princ, realm, "abcdefg", time.Unix(100, 0), 1, 18)
	kt.AddEntry(princ, realm, "abcdefg", time.Unix(200, 0), 2, 18)
	kt.AddEntry(princ, realm, "abcdefg", time.Unix(300, 0), 3, 18)
	kt.AddEntry(princ, realm, "abcdefg", time.Unix(400, 0), 4, 18)
	kt.AddEntry(princ, realm, "abcdefg", time.Unix(350, 0), 5, 18)
	kt.AddEntry("HTTP/other.test.gokrb5", realm, "abcdefg", time.Unix(500, 0), 5, 18)

	pn := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, princ)

	_, kvno, err := kt.GetEncryptionKey(pn, realm, 0, 18)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, 4, kvno)
	_, kvno, err = kt.GetEncryptionKey(pn, realm, 3, 18)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, 3, kvno)
}
