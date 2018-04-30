package kadmin

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"gopkg.in/jcmturner/gokrb5.v4/messages"
)

const (
	verisonHex = "0xff80"
)

type Message struct {
	APREQ   messages.APReq
	KRBPriv messages.KRBPriv
}

func (m *Message) Marshal() (b []byte, err error) {
	vb, _ := hex.DecodeString(verisonHex)
	b = append(b, vb...)
	ab, e := m.APREQ.Marshal()
	if e != nil {
		err = fmt.Errorf("error marshaling AP_REQ: %v", e)
		return
	}
	if len(ab) > math.MaxUint16 {
		err = errors.New("length of AP_REQ greater then max Uint16 size")
		return
	}
	al := make([]byte, 2)
	binary.BigEndian.PutUint16(al, uint16(len(ab)))
	b = append(b, al...)
	b = append(b, ab...)
	pb, e := m.KRBPriv.Marshal()
	if e != nil {
		err = fmt.Errorf("error marshaling KRB_Priv: %v", e)
		return
	}
	b = append(b, pb...)
	if len(b)+2 > math.MaxUint16 {
		err = errors.New("length of message greater then max Uint16 size")
		return
	}
	ml := make([]byte, 2)
	binary.BigEndian.PutUint16(ml, uint16(len(b)+2))
	b = append(ml, b...)
	return
}
