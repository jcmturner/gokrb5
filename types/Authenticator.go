package types

import (
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/iana"
	"github.com/jcmturner/gokrb5/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/iana/nametype"
	"time"
	"github.com/jcmturner/gokrb5/asn1tools"
)

/*Authenticator   ::= [APPLICATION 2] SEQUENCE  {
authenticator-vno       [0] INTEGER (5),
crealm                  [1] Realm,
cname                   [2] PrincipalName,
cksum                   [3] Checksum OPTIONAL,
cusec                   [4] Microseconds,
ctime                   [5] KerberosTime,
subkey                  [6] EncryptionKey OPTIONAL,
seq-number              [7] UInt32 OPTIONAL,
authorization-data      [8] AuthorizationData OPTIONAL
}

   cksum
      This field contains a checksum of the application data that
      accompanies the KRB_AP_REQ, computed using a key usage value of 10
      in normal application exchanges, or 6 when used in the TGS-REQ
      PA-TGS-REQ AP-DATA field.

*/

type Authenticator struct {
	AVNO              int               `asn1:"explicit,tag:0"`
	CRealm            string            `asn1:"generalstring,explicit,tag:1"`
	CName             PrincipalName     `asn1:"explicit,tag:2"`
	Cksum             Checksum          `asn1:"explicit,optional,tag:3"`
	Cusec             int               `asn1:"explicit,tag:4"`
	CTime             time.Time         `asn1:"generalized,explicit,tag:5"`
	SubKey            EncryptionKey     `asn1:"explicit,optional,tag:6"`
	SeqNumber         int               `asn1:"explicit,optional,tag:7"`
	AuthorizationData AuthorizationData `asn1:"explicit,optional,tag:8"`
}

func NewAuthenticator(realm, username string) Authenticator {
	t := time.Now()
	return Authenticator{
		AVNO:   iana.PVNO,
		CRealm: realm,
		CName: PrincipalName{
			NameType:   nametype.KRB_NT_PRINCIPAL,
			NameString: []string{username},
		},
		Cksum: Checksum{},
		Cusec: int((t.UnixNano() / int64(time.Microsecond)) - (t.Unix() * 1e6)),
		CTime: t,
	}
}

func (a *Authenticator) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, a, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.Authenticator))
	return err
}

func (a *Authenticator) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*a)
	if err != nil {
		return nil, err
	}
	b = asn1tools.AddASNAppTag(b, asnAppTag.Authenticator)
	return b, nil
}