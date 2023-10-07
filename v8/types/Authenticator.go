// Package types provides Kerberos 5 data types.
package types

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
)

// RFC 4121 Section 4.1.1.1
const (
	Flag_Deleg    = 1
	Flag_Mutual   = 2
	Flag_Replay   = 4
	Flag_Sequence = 8
	Flag_Conf     = 16
	Flag_Integ    = 32
)

// Authenticator - A record containing information that can be shown to have been recently generated using the session
// key known only by the client and server.
// https://tools.ietf.org/html/rfc4120#section-5.5.1
type Authenticator struct {
	AVNO              int               `asn1:"explicit,tag:0"`
	CRealm            string            `asn1:"generalstring,explicit,tag:1"`
	CName             PrincipalName     `asn1:"explicit,tag:2"`
	Cksum             Checksum          `asn1:"explicit,optional,tag:3"`
	Cusec             int               `asn1:"explicit,tag:4"`
	CTime             time.Time         `asn1:"generalized,explicit,tag:5"`
	SubKey            EncryptionKey     `asn1:"explicit,optional,tag:6"`
	SeqNumber         int64             `asn1:"explicit,optional,tag:7"`
	AuthorizationData AuthorizationData `asn1:"explicit,optional,tag:8"`
}

// RFC1964 Section 1.1
type CredDelegation struct {
	BndLength   uint32
	Bnd         []byte
	Flags       uint32
	DelegOption uint16
	DelegLength uint16
	Deleg       []byte
}

// NewAuthenticator creates a new Authenticator.
func NewAuthenticator(realm string, cname PrincipalName) (Authenticator, error) {
	seq, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	if err != nil {
		return Authenticator{}, err
	}
	t := time.Now().UTC()
	return Authenticator{
		AVNO:      iana.PVNO,
		CRealm:    realm,
		CName:     cname,
		Cksum:     Checksum{},
		Cusec:     int((t.UnixNano() / int64(time.Microsecond)) - (t.Unix() * 1e6)),
		CTime:     t,
		SeqNumber: seq.Int64() & 0x3fffffff,
	}, nil
}

// GenerateSeqNumberAndSubKey sets the Authenticator's sequence number and subkey.
func (a *Authenticator) GenerateSeqNumberAndSubKey(keyType int32, keySize int) error {
	seq, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	if err != nil {
		return err
	}
	a.SeqNumber = seq.Int64() & 0x3fffffff
	//Generate subkey value
	sk := make([]byte, keySize, keySize)
	rand.Read(sk)
	a.SubKey = EncryptionKey{
		KeyType:  keyType,
		KeyValue: sk,
	}
	return nil
}

func (a *Authenticator) GetCredDelegation() (*CredDelegation, error) {
	if a.Cksum.CksumType != chksumtype.GSSAPI {
		return nil, fmt.Errorf("Authenticator has no credential delegation")
	}
	var del CredDelegation
	err := del.Unmarshal(a.Cksum.Checksum)
	if err != nil {
		return nil, fmt.Errorf("Error unmarshalling KRB_CRED packet in Authenticator")
	}
	if del.Flags&Flag_Deleg == 0 {
		return nil, nil
	}
	return &del, nil
}

// Unmarshal bytes into the Authenticator.
func (a *Authenticator) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, a, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.Authenticator))
	return err
}

// Marshal the Authenticator.
func (a *Authenticator) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*a)
	if err != nil {
		return nil, err
	}
	b = asn1tools.AddASNAppTag(b, asnAppTag.Authenticator)
	return b, nil
}

func (c *CredDelegation) HasDelegation() bool {
	return c.Flags&Flag_Deleg != 0
}

func (c *CredDelegation) Unmarshal(b []byte) error {
	c.BndLength = binary.LittleEndian.Uint32(b[0:4])
	if c.BndLength != 16 {
		return fmt.Errorf("Invalid BndLength")
	}
	c.Bnd = b[4:20]
	c.Flags = binary.LittleEndian.Uint32(b[20:24])
	if len(b) <= 24 {
		// No delegation to use, but valid otherwise
		return nil
	}

	c.DelegOption = binary.LittleEndian.Uint16(b[24:26])
	c.DelegLength = binary.LittleEndian.Uint16(b[26:28])
	c.Deleg = b[28 : c.DelegLength+28]

	return nil
}
