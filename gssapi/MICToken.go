package gssapi

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"gopkg.in/jcmturner/gokrb5.v6/crypto"
	"gopkg.in/jcmturner/gokrb5.v6/iana/keyusage"
	"gopkg.in/jcmturner/gokrb5.v6/types"
)

/*
From RFC 4121, section 4.2.6.1:

   Use of the GSS_GetMIC() call yields a token (referred as the MIC
   token in this document), separate from the user data being protected,
   which can be used to verify the integrity of that data as received.
   The token has the following format:

         Octet no   Name        Description
         --------------------------------------------------------------
         0..1     TOK_ID     Identification field.  Tokens emitted by
                             GSS_GetMIC() contain the hex value 04 04
                             expressed in big-endian order in this
                             field.
         2        Flags      Attributes field, as described in section
                             4.2.2.
         3..7     Filler     Contains five octets of hex value FF.
         8..15    SND_SEQ    Sequence number field in clear text,
                             expressed in big-endian order.
         16..last SGN_CKSUM  Checksum of the "to-be-signed" data and
                             octet 0..15, as described in section 4.2.4.

   The Filler field is included in the checksum calculation for
   simplicity.

*/
const (
	MICHdrLen = 16 // Length of the MIC Token's header
)

// MICToken represents a GSS API MIC token, as defined in RFC 4121.
// It contains the header fields, the payload (this is not transmitted) and
// the checksum, and provides the logic for converting to/from bytes plus
// computing and verifying checksums
type MICToken struct {
	// const GSS Token ID: 0x0404
	Flags byte // contains three flags: acceptor, sealed, acceptor subkey
	// const Filler: 0xFF 0xFF 0xFF 0xFF 0xFF
	SndSeqNum uint64 // sender's sequence number. big-endian
	Payload   []byte // your data! :)
	Checksum  []byte // checksum of { payload | header }
}

// Return the 2 bytes identifying a GSS API MIC token
func getGssMICTokenId() *[2]byte {
	return &[2]byte{0x04, 0x04}
}

// Return the filler bytes used in header
func fillerBytes() *[5]byte {
	return &[5]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
}

// Marshal the MICToken into a byte slice.
// The payload should have been set and the checksum computed, otherwise an error is returned.
func (mt *MICToken) Marshal() ([]byte, error) {
	if mt.Checksum == nil {
		return nil, errors.New("checksum has not been set")
	}

	bytes := make([]byte, MICHdrLen+len(mt.Checksum))
	copy(bytes[0:MICHdrLen], getMICChecksumHeader(mt.Flags, mt.SndSeqNum)[:])
	copy(bytes[MICHdrLen:], mt.Checksum)

	return bytes, nil
}

// ComputeAndSetChecksum uses the passed encryption key and key usage to compute the checksum over the payload and
// the header, and sets the Checksum field of this MICToken.
// If the payload has not been set or the checksum has already been set, an error is returned.
func (mt *MICToken) ComputeAndSetChecksum(key types.EncryptionKey, keyUsage uint32) error {
	if mt.Payload == nil {
		return errors.New("payload has not been set")
	}
	if mt.Checksum != nil {
		return errors.New("checksum has already been computed")
	}
	checksum, err := mt.ComputeChecksum(key, keyUsage)
	if err != nil {
		return err
	}
	mt.Checksum = checksum
	return nil
}

// ComputeChecksum computes and returns the checksum of this token, computed using the passed key and key usage.
// Confirms to RFC 4121 in that the checksum will be computed over { body | header }.
// In the context of Kerberos MIC tokens, mostly keyusage GSSAPI_ACCEPTOR_SIGN (=23)
// and GSSAPI_INITIATOR_SIGN (=25) will be used.
// Note: This will NOT update the struct's Checksum field.
func (mt *MICToken) ComputeChecksum(key types.EncryptionKey, keyUsage uint32) ([]byte, error) {
	if mt.Payload == nil {
		return nil, errors.New("cannot compute checksum with uninitialized payload")
	}
	checksumMe := make([]byte, MICHdrLen+len(mt.Payload))
	copy(checksumMe[0:], mt.Payload)
	copy(checksumMe[len(mt.Payload):], getMICChecksumHeader(mt.Flags, mt.SndSeqNum))

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	return encType.GetChecksumHash(key.KeyValue, checksumMe, keyUsage)
}

// Build a header suitable for a checksum computation
func getMICChecksumHeader(flags byte, senderSeqNum uint64) []byte {
	header := make([]byte, MICHdrLen)
	copy(header[0:2], getGssMICTokenId()[:])
	header[2] = flags
	copy(header[3:8], fillerBytes()[:])
	binary.BigEndian.PutUint64(header[8:16], senderSeqNum)
	return header
}

// Verify Checksum computes the token's checksum with the provided key and usage,
// and compares it to the checksum present in the token.
// In case of any failure, (false, err) is returned, with err an explanatory error.
func (mt *MICToken) VerifyChecksum(key types.EncryptionKey, keyUsage uint32) (bool, error) {
	computed, err := mt.ComputeChecksum(key, keyUsage)
	if err != nil {
		return false, err
	}
	if !hmac.Equal(computed, mt.Checksum) {
		return false, fmt.Errorf(
			"checksum mismatch. Computed: %s, Contained in token: %s",
			hex.EncodeToString(computed), hex.EncodeToString(mt.Checksum))
	}
	return true, nil
}

// Unmarshal bytes into the corresponding MICToken.
// If expectFromAcceptor is true we expect the token to have been emitted by the gss acceptor,
// and will check the according flag, returning an error if the token does not match the expectation.
func (mt *MICToken) Unmarshal(b []byte, expectFromAcceptor bool) error {
	if len(b) < MICHdrLen {
		return errors.New("bytes shorter than hedaer length")
	}
	if !bytes.Equal(getGssMICTokenId()[:], b[0:2]) {
		return fmt.Errorf("wrong Token ID, Expected %s, was %s",
			hex.EncodeToString(getGssMICTokenId()[:]),
			hex.EncodeToString(b[0:2]))
	}
	flags := b[2]
	isFromAcceptor := flags&0x01 == 1
	if isFromAcceptor && !expectFromAcceptor {
		return errors.New("unexpected acceptor flag is set: not expecting a token from the acceptor")
	}
	if !isFromAcceptor && expectFromAcceptor {
		return errors.New("unexpected acceptor flag is not set: expecting a token from the acceptor, not in the initiator")
	}
	if !bytes.Equal(b[3:8], fillerBytes()[:]) {
		return fmt.Errorf("unexpected filler bytes: expecting %s, was %s",
			hex.EncodeToString(fillerBytes()[:]),
			hex.EncodeToString(b[3:8]))
	}

	mt.Flags = flags
	mt.SndSeqNum = binary.BigEndian.Uint64(b[8:16])
	mt.Checksum = b[MICHdrLen:]
	return nil
}

// NewInitiatorMICToken builds a new initiator token (acceptor flag will be set to 0) and computes the authenticated checksum.
// Other flags are set to 0.
// Note that in certain circumstances you may need to provide a sequence number that has been defined earlier.
// This is currently not supported.
func NewInitiatorMICToken(payload []byte, key types.EncryptionKey) (*MICToken, error) {
	token := MICToken{
		Flags:     0x00,
		SndSeqNum: 0,
		Payload:   payload,
	}

	if err := token.ComputeAndSetChecksum(key, keyusage.GSSAPI_INITIATOR_SIGN); err != nil {
		return nil, err
	}

	return &token, nil
}
