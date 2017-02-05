package types

import (
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/types/asnAppTag"
	"time"
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

func (a *Authenticator) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, a, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.Authenticator))
	return err
}
