package gssapi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"gopkg.in/jcmturner/gokrb5.v3/crypto"
	"gopkg.in/jcmturner/gokrb5.v3/iana/keyusage"
	"gopkg.in/jcmturner/gokrb5.v3/types"
)

/*
From RFC 4121, section 4.2.6.2:

   Use of the GSS_Wrap() call yields a token (referred as the Wrap token
   in this document), which consists of a descriptive header, followed
   by a body portion that contains either the input user data in
   plaintext concatenated with the checksum, or the input user data
   encrypted.  The GSS_Wrap() token SHALL have the following format:

         Octet no   Name        Description
         --------------------------------------------------------------
          0..1     TOK_ID    Identification field.  Tokens emitted by
                             GSS_Wrap() contain the hex value 05 04
                             expressed in big-endian order in this
                             field.
          2        Flags     Attributes field, as described in section
                             4.2.2.
          3        Filler    Contains the hex value FF.
          4..5     EC        Contains the "extra count" field, in big-
                             endian order as described in section 4.2.3.
          6..7     RRC       Contains the "right rotation count" in big-
                             endian order, as described in section
                             4.2.5.
          8..15    SND_SEQ   Sequence number field in clear text,
                             expressed in big-endian order.
          16..last Data      Encrypted data for Wrap tokens with
                             confidentiality, or plaintext data followed
                             by the checksum for Wrap tokens without
                             confidentiality, as described in section
                             4.2.4.

Quick notes:
	- "EC" or "Extra Count" refers to the length of the cheksum.
	- "Flags" (complete details in section 4.2.2) is a set of bits:
		- if bit 0 is set, it means the token was sent by the acceptor (generally the kerberized service).
		- bit 1 indicates that the token's payload is encrypted
 		- bit 2 indicates if the message is protected using a subkey defined by the acceptor.
	- When computing checksums, EC and RRC MUST be set to 0.
    - Wrap Tokens are not ASN.1 encoded.
*/
var (
	HdrLen              = 16 // Length of the Wrap Token's header
	GSSWrapTokenID      = [2]byte{0x05, 0x04}
	FillerByte     byte = 0xFF
	ChecksumECRRC       = [4]byte{0x00, 0x00, 0x00, 0x00}
	ENC                 = binary.BigEndian
)

type WrapToken struct {
	// const GSS Token ID: 0x0504
	Flags byte // acceptor, sealed, acceptor subkey
	// const Filler: 0xFF
	EC       uint16 // checksum length. big-endian
	RRC      uint16 // right rotation count. big-endian
	SND_SEQ  uint64 // sender's sequence number. big-endian
	Payload  []byte // your data! :)
	CheckSum []byte // authenticated checksum of { payload | header }
}

// Get them bytes!
func (wt *WrapToken) Marshal() ([]byte, error) {
	if wt.CheckSum == nil {
		return nil, errors.New("Checksum has not been set.")
	}
	if wt.Payload == nil {
		return nil, errors.New("Payload has not been set.")
	}

	pldOffset := HdrLen                    // Offset of the payload in the token
	chkSOffset := HdrLen + len(wt.Payload) // Offset of the checksum in the token

	bytes := make([]byte, chkSOffset+int(wt.EC))
	copy(bytes[0:], GSSWrapTokenID[:])
	bytes[2] = wt.Flags
	bytes[3] = FillerByte
	ENC.PutUint16(bytes[4:6], wt.EC)
	ENC.PutUint16(bytes[6:8], wt.RRC)
	ENC.PutUint64(bytes[8:16], wt.SND_SEQ)
	copy(bytes[pldOffset:], wt.Payload)
	copy(bytes[chkSOffset:], wt.CheckSum)
	return bytes, nil
}

func (wt *WrapToken) ComputeAndSetCheckSum(key types.EncryptionKey, keyUsage uint32) error {
	if wt.Payload == nil {
		return errors.New("Payload has not been set.")
	}
	if wt.CheckSum != nil {
		return errors.New("Checksum has already been computed.")
	}
	chkSum, cErr := wt.ComputeCheckSum(key, keyUsage)
	if cErr != nil {
		return cErr
	}
	wt.CheckSum = chkSum
	return nil
}

// Compute and return the checksum of this token, computed using the passed key and key usage
// Conforms to RFC 4121 in that the checksum will be computed over { body | header },
// with the EC and RRC flags zeroed out.
// In the context of Kerberos Wrap tokens, mostly keyusage's GSSAPI_ACCEPTOR_SEAL (=22)
// and GSSAPI_INITIATOR_SEAL (=24) will be used.
// Note: This will NOT update the struct's Checksum field.
func (wt *WrapToken) ComputeCheckSum(key types.EncryptionKey, keyUsage uint32) ([]byte, error) {
	if wt.Payload == nil {
		return nil, errors.New("cannot compute checksum with uninitialized payload")
	}
	// Build a slice containing { payload | header }
	checksumMe := make([]byte, HdrLen+len(wt.Payload))
	copy(checksumMe[0:], wt.Payload)
	copy(checksumMe[len(wt.Payload):], getChecksumHeader(wt.Flags, wt.SND_SEQ))

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	return encType.GetChecksumHash(key.KeyValue, checksumMe, keyUsage)
}

// Build a header suitable for a checksum computation
func getChecksumHeader(flags byte, senderSeqNum uint64) []byte {
	header := make([]byte, 16)
	copy(header[0:], []byte{0x05, 0x04, flags, 0xFF, 0x00, 0x00, 0x00, 0x00})
	ENC.PutUint64(header[8:], senderSeqNum)
	return header
}

// Compute the payload + header checksum with the provided key and usage,
// and compare it to the checksum present in the token
func (wt *WrapToken) VerifyCheckSum(key types.EncryptionKey, keyUsage uint32) (bool, error) {
	computed, cErr := wt.ComputeCheckSum(key, keyUsage)
	if cErr != nil {
		return false, cErr
	}
	if !bytes.Equal(computed, wt.CheckSum) {
		return false, errors.New(
			fmt.Sprintf("Checksum mismatch. Computed: %s, Contained in token: %s",
				hex.EncodeToString(computed), hex.EncodeToString(wt.CheckSum)))
	}
	return true, nil
}

// Parse a wrap token
// if expectFromAcceptor is true, we expect the token to have been emitted by the gss acceptor,
// and will check the according flag
func UnmarshalWrapToken(b []byte, expectFromAcceptor bool) (*WrapToken, error) {
	// Check if we can read a whole header
	if len(b) < 16 {
		return nil, errors.New("bytes shorter than header length.")
	}
	// Is the Token ID correct?
	if !bytes.Equal(GSSWrapTokenID[:], b[0:2]) {
		return nil, errors.New(
			fmt.Sprintf("Wrong Token ID. Expected %s, was %s",
				hex.EncodeToString(GSSWrapTokenID[:]),
				hex.EncodeToString(b[0:2])))
	}
	// Check the acceptor flag
	flags := b[2]
	isFromAcceptor := flags&0x01 == 1
	if isFromAcceptor && !expectFromAcceptor {
		return nil, errors.New("Unexpected acceptor flag is set. not expecting a token from the acceptor.")
	}
	if !isFromAcceptor && expectFromAcceptor {
		return nil, errors.New("Expected acceptor flag is not set. expecting a token from the acceptor, not the initiator.")
	}
	// Check the filler byte
	if b[3] != FillerByte {
		return nil, errors.New(
			fmt.Sprintf("Unexpected filler byte: expecting 0xFF, was %s ", hex.EncodeToString(b[3:4])))
	}
	checksumL := ENC.Uint16(b[4:6])
	// Sanity check on the checksum length
	if int(checksumL) > len(b)-HdrLen {
		return nil, errors.New(
			fmt.Sprintf("Inconsistent checksum length. %d bytes to parse, checksum length is %d", len(b), checksumL))
	}
	rrc := ENC.Uint16(b[6:8])
	seqNum := ENC.Uint64(b[8:16])
	payload := b[16 : len(b)-int(checksumL)]
	checksum := b[len(b)-int(checksumL):]
	return &WrapToken{
		Flags:    flags,
		EC:       checksumL,
		RRC:      rrc,
		SND_SEQ:  seqNum,
		Payload:  payload,
		CheckSum: checksum,
	}, nil
}

// Build a new initiator token (acceptor flag will be set to 0) and compute the authenticated checksum.
// Other flags are set to 0, and the RRC and sequence number are initialized to 0.
// Note that in certain circumstances you may need to provide a sequence number that has been defined earlier,
// this is currently not supported.
func NewInitiatorToken(payload []byte, key types.EncryptionKey) (*WrapToken, error) {
	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	token := WrapToken{
		Flags: 0x00, // all zeroed out (this is a token sent by the initiator)
		// Checksum size: lenth of output of the HMAC function, in bytes.
		EC:      uint16(encType.GetHMACBitLength() / 8),
		RRC:     0,
		SND_SEQ: 0,
		Payload: payload,
	}

	if err := token.ComputeAndSetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}

	return &token, nil
}
