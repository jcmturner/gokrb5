package gssapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ===== Almost const 2 bytes values to represent various values from GSS API RFCs
// 13 bytes Independent Token Header as per https://www.rfc-editor.org/rfc/rfc2743#page-81
//   1. 0x60         -- Tag for [APPLICATION 0] SEQUENCE
//   2. 0x30         -- Token length octets (lengths of elements in 3-5 + actual WrapToken v1)
//   3. 0x06         -- Tag for OBJECT IDENTIFIER
//   4. 0x09         -- Object identifier length (lengths of elements in 5)
//   5. 0x2a to 0x02 -- Object identifier octets
var GSS_HEADER                = [13]byte{0x60, 0x2b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}

// 2 bytes identifying GSS API Wrap token v1
var TOK_ID                    = [2]byte{0x02, 0x01}

// Filler in WrapToken v1
var FILLER                    = [2]byte{0xFF, 0xFF}

// Use DES MAC MD5 checksum - RFC 1964
var SGN_ALG_DES_MAC_MD5       = [2]byte{0x00, 0x00}
	
// Use DES MAC  checksum - RFC 1964
var SGN_ALG_DES_MAC           = [2]byte{0x02, 0x00}
	
// Use HMAC SHA1 DES3 KD checksum - RFC 1964
var SGN_ALG_HMAC_SHA1_DES3_KD = [2]byte{0x04, 0x00}

// Use HMAC MD5 ARCFOUR checksum - RFC ?
var SGN_ALG_HMAC_MD5_ARCFOUR  = [2]byte{0x11, 0x00}

// Use NONE encryption to seal
var SEAL_ALG_NONE             = [2]byte{0xFF, 0xFF}

// Use DES CBC encryption to seal
var SEAL_ALG_DES              = [2]byte{0x00, 0x00}

// Use DES3 KD encryption to seal
var SEAL_ALG_DES3_KD          = [2]byte{0x02, 0x00}

// Use ARCFOUR HMAC encryption to seal
var SEAL_ALG_ARCFOUR_HMAC     = [2]byte{0x10, 0x00}
// =====


// WrapTokenV1 represents a GSS API Wrap token v1, as defined in RFC 1964.
// It contains the header fields, the payload and the checksum, and provides
// the logic for converting to/from bytes plus computing and verifying checksums
// This specific Token is for RC4-HMAC Wrap as per https://datatracker.ietf.org/doc/html/rfc4757#section-7.3
type WrapTokenV1 struct {
	// const GSS Token ID: 0x02 0x01
	SGN_ALG  []byte // Checksum algorithm indicator
	SEAL_ALG []byte // Seal algorithm indicator

	// const Filler: 0xFF 0xFF
	// SndSeqNum  uint64 // Encrypted sender's sequence number: big-endian
	SndSeqNum  []byte // Encrypted sender's sequence number: big-endian
	CheckSum   []byte // Checksum of plaintext padded data: { payload | header }
	Confounder []byte // Random confounder
	Payload    []byte // Encrypted or plaintext padded data
}

// Marshal the WrapToken into a byte slice.
// The payload & checksum should be present, otherwise an error is returned.
func (wt *WrapTokenV1) Marshal(key types.EncryptionKey) ([]byte, error) {
	if wt.CheckSum == nil {
		return nil, errors.New("Token SGN_CKSUM has not been set")
	}
	if wt.Payload == nil {
		return nil, errors.New("Token Payload has not been set")
	}

	// { len(GSS_HEADER) = 13 | len(TOKEN.HEADER) + len (TOKEN.SGN_ALG) + len(TOKEN.SEAL_ALG) + len(FILLER) + len(SND_SEQ) + len(SGN_CHSUM) + len(Confounder) = 32 | len (Payload)  }
	bytes := make([]byte, 13 + 32 + len(wt.Payload))
	copy(bytes[0:],    GSS_HEADER[:]) // Final token needs to have GSS_HEADER (as per RFC 2743)
	copy(bytes[13:],   TOK_ID[:])     // Insert TOK_ID
	copy(bytes[15:17], wt.SGN_ALG)    // Insert SGN_ALG
	copy(bytes[17:19], wt.SEAL_ALG)   // Insert SEAL_ALG
	copy(bytes[19:21], FILLER[:])     // Insert Filler

	wt.encryptSndSeqNum(key.KeyValue, wt.CheckSum)

	copy(bytes[21:29], wt.SndSeqNum)  // Insert SND_SEQ
	copy(bytes[29:37], wt.CheckSum)   // Insert SGN_CKSUM
	copy(bytes[37:45], wt.Confounder) // Insert Confounder
	copy(bytes[45:],   wt.Payload)    // Insert Data

	// Now we need to calculate the final length of the WrapToken (including GSS_HEADER minus first 2 bytes)
	// and alter 2nd byte of GSS_HEADER to set the length
	tokenLength     := len(bytes) - 2
	tokenLengthByte := byte(tokenLength)
	bytes[1]         = tokenLengthByte

	return bytes, nil
}

func (wt *WrapTokenV1) encryptSndSeqNum(key []byte, checksum []byte) (error) {
	if wt.SndSeqNum == nil {
		return errors.New("Token SND_SEQ has not been set")
	}

	tb := []byte{0x00, 0x00, 0x00, 0x00}

	mac := hmac.New(md5.New, key)
	mac.Write(tb)
	interimHash := mac.Sum(nil)

	mac = hmac.New(md5.New, interimHash)
	mac.Write(checksum)
	encryptHash := mac.Sum(nil)

	rc4Encryption, err := rc4.NewCipher(encryptHash)
	if err != nil {
		return err
	}

	rc4Encryption.XORKeyStream(wt.SndSeqNum, wt.SndSeqNum)
	return nil
}

// ComputeCheckSum computes and returns the checksum of this token, computed using the passed key and key usage.
// Note: This will NOT update the struct's Checksum field.
func (wt *WrapTokenV1) computeCheckSum(key types.EncryptionKey, keyUsage uint32) ([]byte, error) {
	if wt.Payload == nil {
		return nil, errors.New("cannot compute checksum with uninitialized payload")
	}

	if wt.Confounder == nil {
		return nil, errors.New("cannot compute checksum with uninitialized confounder")
	}

	// Build a slice containing { header=8 | confounder | payload }
	checksumMe := make([]byte, 8 + len(wt.Confounder) + len(wt.Payload))
	copy(checksumMe[0:], TOK_ID[:])
	copy(checksumMe[2:], wt.SGN_ALG)
	copy(checksumMe[4:], wt.SEAL_ALG)
	copy(checksumMe[6:], FILLER[:])
	copy(checksumMe[8:], wt.Confounder)
	copy(checksumMe[8 + len(wt.Confounder):], wt.Payload)

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	checksumHash, err := encType.GetChecksumHash(key.KeyValue, checksumMe, keyUsage)
	if err!= nil {
		return nil, err
	}

	return checksumHash[:8], nil
}

// Verify computes the token's checksum with the provided key and usage,
// and compares it to the checksum present in the token.
// In case of any failure, (false, Err) is returned, with Err an explanatory error.
func (wt *WrapTokenV1) Verify(key types.EncryptionKey, keyUsage uint32) (bool, error) {
	computed, cErr := wt.computeCheckSum(key, keyUsage)
	if cErr != nil {
		return false, cErr
	}
	if !hmac.Equal(computed, wt.CheckSum) {
		return false, fmt.Errorf(
			"checksum mismatch. Computed: %s, Contained in token: %s",
			hex.EncodeToString(computed), hex.EncodeToString(wt.CheckSum))
	}
	return true, nil
}


// Unmarshal bytes into the corresponding WrapTokenV1.
func (wt *WrapTokenV1) Unmarshal(b []byte, expectFromAcceptor bool) error {
  // This function maps onto GSS_Wrap() from RFC 1964
  //   The GSS_Wrap() token has the following format:
  //
  //  Byte no      Name         Description
  //   0..1       TOK_ID        Identification field.
  //                            Tokens emitted by GSS_Wrap() contain
  //                            the hex value 02 01 in this field.
  //   2..3       SGN_ALG       Checksum algorithm indicator.
  //                            00 00 - DES MAC MD5 << please don't use this one as per https://datatracker.ietf.org/doc/html/rfc6649
  //                            02 00 - DES MAC     << please don't use this one as per https://datatracker.ietf.org/doc/html/rfc6649
  //                            01 00 - MD2.5       << please don't use this one as per https://datatracker.ietf.org/doc/html/rfc6649
  //                            11 00 - HMAC MD5 ARCFOUR
  //   4..5       SEAL_ALG      ff ff - none
  //                            00 00 - DES << please don't use this one as per https://datatracker.ietf.org/doc/html/rfc6649
  //                            02 00 - DES3-KD
  //                            10 00 - ARCFOUR-HMAC
  //   6..7       Filler        Contains ff ff
  //   8..15      SND_SEQ       Encrypted sequence number field.
  //   16..23     SGN_CKSUM     Checksum of plaintext padded data,
  //                            calculated according to algorithm
  //                            specified in SGN_ALG field.
  //   24..31     Confounder    Random confounder
  //   32..last   Data          Encrypted, according to algorithm specified
	//                            in SEAL_ALG field or plaintext padded data
	start_position := 0
	
	// Check if we can read a whole header
	if len(b) < 21 {
		return errors.New("bytes shorter than header length")
	}

	if b[0] == 0x60 {
		start_position = 13
	}

	// Is the Token ID correct?
	if !bytes.Equal(TOK_ID[:], b[start_position:start_position+2]) {
		return fmt.Errorf("wrong Token ID. Expected %s, was %s",
			hex.EncodeToString(TOK_ID[:]),
			hex.EncodeToString(b[start_position:start_position+2]))
	}

	// Check SGN_ALG
	switch {
		case bytes.Equal(SGN_ALG_DES_MAC_MD5[:],       b[start_position+2:start_position+4]):
			break
		case bytes.Equal(SGN_ALG_DES_MAC[:],           b[start_position+2:start_position+4]):
			break
		case bytes.Equal(SGN_ALG_HMAC_SHA1_DES3_KD[:], b[start_position+2:start_position+4]):
			break
		case bytes.Equal(SGN_ALG_HMAC_MD5_ARCFOUR[:],  b[start_position+2:start_position+4]):
			break
		default:
			return fmt.Errorf("Unsupported SGN_ALG value: %s", hex.EncodeToString(b[start_position+2:start_position+4]))
	}
	wt.SGN_ALG = b[start_position+2:start_position+4]

	// Check SEAL_ALG
	switch {
		case bytes.Equal(SEAL_ALG_NONE[:], b[start_position+4:start_position+6]):
			break
		case bytes.Equal(SEAL_ALG_DES[:], b[start_position+4:start_position+6]):
			break
		case bytes.Equal(SEAL_ALG_DES3_KD[:], b[start_position+4:start_position+6]):
			break
		case bytes.Equal(SEAL_ALG_ARCFOUR_HMAC[:], b[start_position+4:start_position+6]):
			break
		default:
			return fmt.Errorf("Unsupported SEAL_ALG value: %s", hex.EncodeToString(b[start_position+4:start_position+6]))
	}
	wt.SEAL_ALG = b[start_position+4:start_position+6]

	// Check the filler byte
	if !bytes.Equal(FILLER[:], b[start_position+6:start_position+8]) {
		return fmt.Errorf("unexpected filler byte: expecting 0xFFFF, was %s", hex.EncodeToString(b[start_position+6:start_position+8]))
	}

	wt.SndSeqNum  = b[start_position+8:start_position+16]
	wt.CheckSum   = b[start_position+16:start_position+24]
	wt.Confounder = b[start_position+24:start_position+32]
	wt.Payload    = b[start_position+32:]

	return nil
}

// NewInitiatorWrapToken builds a new initiator token
func NewInitiatorWrapTokenV1(initial_toke *WrapTokenV1, key types.EncryptionKey) (*WrapTokenV1, error) {
	// Create random Confounder
	confounder := make([]byte, 8)
	_, err     := rand.Read(confounder)
	if err != nil {
		return nil, err
	}

	// We need to pad the data (confounder + payload) before we do anything else
	// as per https://datatracker.ietf.org/doc/html/rfc1964#section-1.2.2.3
	// However Kafka sends already padded data so we can ignore it

	// Create new SND_SEQ based on request SND_SEQ
	new_seq_num := make([]byte, 8)
	copy(new_seq_num[:4], initial_toke.SndSeqNum[4:])
	copy(new_seq_num[4:], []byte{0x00, 0x00, 0x00, 0x00})

	token := WrapTokenV1{
		SGN_ALG:    initial_toke.SGN_ALG,
		SEAL_ALG:   initial_toke.SEAL_ALG,
		SndSeqNum:  new_seq_num[:],
		Confounder: confounder[:],
		Payload:    initial_toke.Payload[:],
	}

	// keyusage.GSSAPI_ACCEPTOR_SIGN (=23) resolves into derivation salt = 13 which is the one we must use for RC4 WrapTokenV1
	// even though https://datatracker.ietf.org/doc/html/rfc4757#section-7.3 suggests to use derivation salt = 15 (which is actually MIC's salt)
	if err := token.SetCheckSum(key, keyusage.GSSAPI_ACCEPTOR_SIGN); err != nil {
		return nil, err
	}

	return &token, nil
}

// SetCheckSum uses the passed encryption key and key usage to compute the checksum over the payload and
// the header, and sets the CheckSum field of this WrapToken.
// If the payload has not been set or the checksum has already been set, an error is returned.
func (wt *WrapTokenV1) SetCheckSum(key types.EncryptionKey, keyUsage uint32) error {
	if wt.Payload == nil {
		return errors.New("payload has not been set")
	}
	if wt.CheckSum != nil {
		return errors.New("checksum has already been computed")
	}

	chkSum, cErr := wt.computeCheckSum(key, keyUsage)
	if cErr != nil {
		return cErr
	}

	wt.CheckSum = chkSum
	return nil
}
