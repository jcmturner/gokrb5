// +build disabled

package crypto

import (
	"encoding/hex"
	"github.com/jcmturner/gokrb5/crypto/engine"
	"github.com/stretchr/testify/assert"
	"testing"
)

//func TestAesCtsHmacSha196_Encrypt_Decrypt(t *testing.T) {
//	iv := make([]byte, 16)
//	key, _ := hex.DecodeString("636869636b656e207465726979616b69")
//	var tests = []struct {
//		plain  string
//		cipher string
//		nextIV string
//	}{
//		//Test vectors from RFC 3962 Appendix B
//		{"4920776f756c64206c696b652074686520", "c6353568f2bf8cb4d8a580362da7ff7f97", "c6353568f2bf8cb4d8a580362da7ff7f"},
//		{"4920776f756c64206c696b65207468652047656e6572616c20476175277320", "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5", "fc00783e0efdb2c1d445d4c8eff7ed22"},
//		{"4920776f756c64206c696b65207468652047656e6572616c2047617527732043", "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584", "39312523a78662d5be7fcbcc98ebf5a8"},
//		{"4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c", "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5", "b3fffd940c16a18c1b5549d2f838029e"},
//		{"4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20", "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8", "9dad8bbb96c4cdc03bc103e1a194bbd8"},
//		{"4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e", "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8", "4807efe836ee89a526730dbc2f7bc840"},
//	}
//	var e Aes128CtsHmacSha96
//	for i, test := range tests {
//		m, _ := hex.DecodeString(test.plain)
//		niv, c, err := encryptCTS(key, iv, m, e)
//		if err != nil {
//			t.Errorf("Encryption failed for test %v: %v", i+1, err)
//		}
//		assert.Equal(t, test.cipher, hex.EncodeToString(c), "Encrypted result not as expected")
//		assert.Equal(t, test.nextIV, hex.EncodeToString(niv), "Next state IV not as expected")
//	}
//	//t.Log("AES CTS Encryption tests finished")
//	for i, test := range tests {
//		b, _ := hex.DecodeString(test.cipher)
//		p, err := decryptCTS(key, b, e)
//		if err != nil {
//			t.Errorf("Decryption failed for test %v: %v", i+1, err)
//		}
//		assert.Equal(t, test.plain, hex.EncodeToString(p), "Decrypted result not as expected")
//	}
//	//t.Log("AES CTS Decryption tests finished")
//}

func TestAes128CtsHmacSha256128_StringToKey(t *testing.T) {
	// Test vectors from RFC 8009 Appendix A
	// Random 16bytes in test vector as string
	r, _ := hex.DecodeString("10DF9DD783E5BC8ACEA1730E74355F61")
	s := string(r)
	var tests = []struct {
		iterations int
		phrase     string
		salt       string
		saltp      string
		key        string
	}{
		{32768, "password", s + "ATHENA.MIT.EDUraeburn", "6165733132382d6374732d686d61632d7368613235362d3132380010df9dd783e5bc8acea1730e74355f61415448454e412e4d49542e4544557261656275726e", "089bca48b105ea6ea77ca5d2f39dc5e7"},
	}
	var e Aes128CtsHmacSha256128
	for _, test := range tests {
		saltp := e.getSaltP(test.salt)
		assert.Equal(t, test.saltp, hex.EncodeToString(([]byte(saltp))), "SaltP not as expected")

		k, _ := e.StringToKey(test.phrase, test.salt, IterationsToS2kparams(test.iterations))
		assert.Equal(t, test.key, hex.EncodeToString(k), "String to Key not as expected")

	}
}

func TestAes128CtsHmacSha256128_DeriveKey(t *testing.T) {
	// Test vectors from RFC 8009 Appendix A
	protocolBaseKey, _ := hex.DecodeString("3705d96080c17728a0e800eab6e0d23c")
	testUsage := uint32(2)
	var e Aes128CtsHmacSha256128
	k, err := e.DeriveKey(protocolBaseKey, engine.GetUsageKc(testUsage))
	if err != nil {
		t.Fatalf("Error deriving checksum key: %v", err)
	}
	assert.Equal(t, "b31a018a48f54776f403e9a396325dc3", hex.EncodeToString(k), "Checksum derived key not as epxected")
	k, err = e.DeriveKey(protocolBaseKey, engine.GetUsageKe(testUsage))
	if err != nil {
		t.Fatalf("Error deriving encryption key: %v", err)
	}
	assert.Equal(t, "9b197dd1e8c5609d6e67c3e37c62c72e", hex.EncodeToString(k), "Encryption derived key not as epxected")
	k, err = e.DeriveKey(protocolBaseKey, engine.GetUsageKi(testUsage))
	if err != nil {
		t.Fatalf("Error deriving integrity key: %v", err)
	}
	assert.Equal(t, "9fda0e56ab2d85e1569a688696c26a6c", hex.EncodeToString(k), "Integrity derived key not as epxected")
}

func TestAes128CtsHmacSha256128_Cypto(t *testing.T) {
	protocolBaseKey, _ := hex.DecodeString("3705d96080c17728a0e800eab6e0d23c")
	testUsage := uint32(2)
	var tests = []struct {
		plain      string
		confounder string
		ke         string
		ki         string
		encrypted  string // AESOutput
		hash       string // TruncatedHMACOutput
		cipher     string // Ciphertext(AESOutput|HMACOutput)
	}{
		// Test vectors from RFC 8009 Appendix A
		{"", "7e5895eaf2672435bad817f545a37148", "9b197dd1e8c5609d6e67c3e37c62c72e", "9fda0e56ab2d85e1569a688696c26a6c", "ef85fb890bb8472f4dab20394dca781d", "ad877eda39d50c870c0d5a0a8e48c718", "ef85fb890bb8472f4dab20394dca781dad877eda39d50c870c0d5a0a8e48c718"},
		{"000102030405", "7bca285e2fd4130fb55b1a5c83bc5b24", "9b197dd1e8c5609d6e67c3e37c62c72e", "9fda0e56ab2d85e1569a688696c26a6c", "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6", "877ce99e247e52d16ed4421dfdf8976c", "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6877ce99e247e52d16ed4421dfdf8976c"},
	}
	var e Aes128CtsHmacSha256128
	for i, test := range tests {
		m, _ := hex.DecodeString(test.plain)
		b, _ := hex.DecodeString(test.encrypted)
		ke, _ := hex.DecodeString(test.ke)
		cf, _ := hex.DecodeString(test.confounder)
		cfm := append(cf, m...)

		_, c, err := e.Encrypt(ke, cfm)
		if err != nil {
			t.Errorf("Encryption failed for test %v: %v", i+1, err)
		}
		assert.Equal(t, test.encrypted, hex.EncodeToString(c), "Encrypted result not as expected - test %v", i)

		ivz := make([]byte, e.GetConfounderByteSize())
		hm := append(ivz, b...)
		mac, _ := engine.GetIntegrityHash(hm, protocolBaseKey, testUsage, e)
		assert.Equal(t, test.hash, hex.EncodeToString(mac), "HMAC result not as expected - test %v", i)

		p, err := e.Decrypt(ke, b)
		//Remove the confounder bytes
		p = p[e.GetConfounderByteSize():]
		if err != nil {
			t.Errorf("Decryption failed for test %v: %v", i+1, err)
		}
		assert.Equal(t, test.plain, hex.EncodeToString(p), "Decrypted result not as expected - test %v", i)
	}
}
