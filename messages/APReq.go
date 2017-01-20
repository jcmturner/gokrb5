package messages

import (
	"encoding/asn1"
	"github.com/jcmturner/gokrb5/types"
)

/*AP-REQ          ::= [APPLICATION 14] SEQUENCE {
pvno            [0] INTEGER (5),
msg-type        [1] INTEGER (14),
ap-options      [2] APOptions,
ticket          [3] Ticket,
authenticator   [4] EncryptedData -- Authenticator
}

APOptions       ::= KerberosFlags
-- reserved(0),
-- use-session-key(1),
-- mutual-required(2)*/

type APReq struct {
	PVNO          int                 `asn1:"explicit,tag:0"`
	MsgType       int                 `asn1:"explicit,tag:1"`
	APOptions     asn1.BitString      `asn1:"explicit,tag:2"`
	Ticket        types.Ticket        `asn1:"explicit,tag:3"`
	Authenticator types.EncryptedData `asn1:"explicit,tag:4"`
}
