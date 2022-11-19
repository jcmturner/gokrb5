package gssapi

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
)

const (
	// Length of the Wrap Token v1 header
	TOKEN_NO_CKSUM_SIZE = 8
)

// ===== Almost const 2 bytes values to represent various values from GSS API RFCs
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
	SGN_ALG  uint16 // Checksum algorithm indicator: big-endian
	SEAL_ALG uint16 // Seal algorithm indicator: big-endian

	// const Filler: 0xFF 0xFF
	SndSeqNum  uint64 // Encrypted sender's sequence number: big-endian
	CheckSum   []byte // Checksum of plaintext padded data: { payload | header }
	Confounder []byte // Random confounder
	Payload    []byte // Encrypted or plaintext padded data
}

// Marshal the WrapToken into a byte slice.
// The payload should have been set and the checksum computed, otherwise an error is returned.
func (wt *WrapTokenV1) Marshal() ([]byte, error) {
	if wt.CheckSum == nil {
		return nil, errors.New("checksum has not been set")
	}
	if wt.Payload == nil {
		return nil, errors.New("payload has not been set")
	}

	bytes := make([]byte, 24 + len(wt.Payload))
	copy(bytes[0:],  TOK_ID[:])                           // Insert TOK_ID
	copy(bytes[2:4], SGN_ALG_HMAC_MD5_ARCFOUR[:])         // Insert SGN_ALG
	copy(bytes[4:6], SEAL_ALG_NONE[:])                    // Insert SEAL_ALG
	copy(bytes[6:8], FILLER[:])                           // Insert Filler

	binary.BigEndian.PutUint64(bytes[8:16], wt.SndSeqNum) // Insert SND_SEQ
	copy(bytes[16:24], wt.CheckSum)                       // Insert SGN_CKSUM
	copy(bytes[24:], wt.Payload)                          // Insert Data

	return bytes, nil
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

// ComputeCheckSum computes and returns the checksum of this token, computed using the passed key and key usage.
// Note: This will NOT update the struct's Checksum field.
func (wt *WrapTokenV1) computeCheckSum(key types.EncryptionKey, keyUsage uint32) ([]byte, error) {
	if wt.Payload == nil {
		return nil, errors.New("cannot compute checksum with uninitialized payload")
	}

	if wt.Confounder == nil {
		return nil, errors.New("cannot compute checksum with uninitialized confounder")
	}

	// Build a slice containing { header | confounder | payload }
	header := getChecksumHeaderV1()
	checksumMe := make([]byte, len(header) + len(wt.Confounder) + len(wt.Payload))
	copy(checksumMe[0:], header)
	copy(checksumMe[len(header):], wt.Confounder)
	copy(checksumMe[len(header) + len(wt.Confounder):], wt.Payload)

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	fmt.Printf("keyType: %d, keyValue: %s, keyUsage: %d, checksumMe: %s\n", key.KeyType, hex.EncodeToString(key.KeyValue), keyUsage, hex.EncodeToString(checksumMe))

	checksumHash, err := encType.GetChecksumHash(key.KeyValue, checksumMe, keyUsage)

	if err!= nil {
		return nil, err
	}

	return checksumHash[:8], nil
}

// Build a header suitable for a checksum computation
func getChecksumHeaderV1() []byte {
	header := make([]byte, 8)
	copy(header[0:], TOK_ID[:])
	copy(header[2:], SGN_ALG_HMAC_MD5_ARCFOUR[:])
	copy(header[4:], SEAL_ALG_ARCFOUR_HMAC[:])
	copy(header[6:], FILLER[:])

	return header
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
  //                            00 00 - DES MAC MD5
  //                            02 00 - DES MAC
  //                            01 00 - MD2.5
  //                            11 00 - HMAC MD5 ARCFOUR
  //   4..5       SEAL_ALG      ff ff - none
  //                            00 00 - DES
  //                            02 00 - DES3-KD
  //                            10 00 - ARCFOUR-HMAC
  //   6..7       Filler        Contains ff ff
  //   8..15      SND_SEQ       Encrypted sequence number field.
  //   16..23     SGN_CKSUM     Checksum of plaintext padded data,
  //                            calculated according to algorithm
  //                            specified in SGN_ALG field.
  //   24..31     Confounder    Random confounder
  //   32..last   Data          encrypted or plaintext padded data
	start_position := 0
	
	// Check if we can read a whole header
	if len(b) < 16 {
		return errors.New("GSSAPI: bytes shorter than header length")
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

	// Check the filler byte
	if !bytes.Equal(FILLER[:], b[start_position+6:start_position+8]) {
		return fmt.Errorf("unexpected filler byte: expecting 0xFFFF, was %s", hex.EncodeToString(b[start_position+6:start_position+8]))
	}

	wt.SndSeqNum  = binary.BigEndian.Uint64(b[start_position+8:start_position+16])
	wt.CheckSum   = b[start_position+16:start_position+24]
	wt.Confounder = b[start_position+24:start_position+32]
	wt.Payload    = b[start_position+32:]
	fmt.Printf("Unmarshal! SndSeqNum: %s, CheckSum: %s, Confounder: %s, Payload: %s\n", hex.EncodeToString(b[start_position+8:start_position+16]), hex.EncodeToString(wt.CheckSum), hex.EncodeToString(wt.Confounder), hex.EncodeToString(wt.Payload))
	return nil
}

// NewInitiatorWrapToken builds a new initiator token (acceptor flag will be set to 0) and computes the authenticated checksum.
// Other flags are set to 0, and the RRC and sequence number are initialized to 0.
// Note that in certain circumstances you may need to provide a sequence number that has been defined earlier.
// This is currently not supported.
func NewInitiatorWrapTokenV1(payload []byte, key types.EncryptionKey) (*WrapTokenV1, error) {
	encType, err := crypto.GetEtype(key.KeyType)
	_ = encType

	if err != nil {
		return nil, err
	}

	token := WrapTokenV1{
		SndSeqNum: 0,
		Confounder: payload[:8],
		Payload:    payload[8:],
	}

	if err := token.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}

	return &token, nil
}
