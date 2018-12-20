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
	MICHdrLen = 16
)

type MICToken struct {
	// const GSS Token ID: 0x0404
	Flags byte // contains three flags: acceptor, sealed, acceptor subkey
	// const Filler: 0xFF 0xFF 0xFF 0xFF 0xFF
	SndSeqNum uint64 // sender's sequence number. big-endian
	Payload   []byte // your data! :)
	Checksum  []byte // checksum of { payload | header }
}

func getGssMICTokenId() *[2]byte {
	return &[2]byte{0x04, 0x04}
}

func fillerBytes() *[5]byte {
	return &[5]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
}

func (mt *MICToken) Marshal() ([]byte, error) {
	if mt.Checksum == nil {
		return nil, errors.New("checksum has not been set")
	}

	bytes := make([]byte, MICHdrLen+len(mt.Checksum))
	copy(bytes[0:MICHdrLen], getMICChecksumHeader(mt.Flags, mt.SndSeqNum)[:])
	copy(bytes[MICHdrLen:], mt.Checksum)

	return bytes, nil
}

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

func getMICChecksumHeader(flags byte, senderSeqNum uint64) []byte {
	header := make([]byte, MICHdrLen)
	copy(header[0:2], getGssMICTokenId()[:])
	header[2] = flags
	copy(header[3:8], fillerBytes()[:])
	binary.BigEndian.PutUint64(header[8:16], senderSeqNum)
	return header
}

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
