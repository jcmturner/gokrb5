package kadmin

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"gopkg.in/jcmturner/gokrb5.v4/messages"
	"gopkg.in/jcmturner/gokrb5.v4/types"
)

const (
	verisonHex = "0xff80"
)

type Request struct {
	APREQ   messages.APReq
	KRBPriv messages.KRBPriv
}

type Reply struct {
	APREP      messages.APRep
	KRBPriv    messages.KRBPriv
	KRBError   messages.KRBError
	IsKRBError bool
	ResultCode uint16
	Result     string
}

func (m *Request) Marshal() (b []byte, err error) {
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

func (m *Reply) Unmarshal(b []byte) error {
	msgLen := int(binary.BigEndian.Uint16(b[0:2]))
	v := int(binary.BigEndian.Uint16(b[2:4]))
	if v != 1 {
		return fmt.Errorf("kadmin reply has incorrect protocol version number: %d", v)
	}
	APRepLen := int(binary.BigEndian.Uint16(b[4:6]))
	if APRepLen != 0 {
		err := m.APREP.Unmarshal(b[6 : 6+APRepLen])
		if err != nil {
			return err
		}
		err = m.KRBPriv.Unmarshal(b[6+APRepLen : msgLen])
		if err != nil {
			return err
		}
	} else {
		m.IsKRBError = true
		m.KRBError.Unmarshal(b[6:msgLen])
		m.ResultCode, m.Result = parseResponse(m.KRBError.EData)
	}
	return nil
}

func parseResponse(b []byte) (c uint16, s string) {
	c = binary.BigEndian.Uint16(b[0:2])
	buf := bytes.NewBuffer(b[2:])
	m := make([]byte, len(b)-2)
	binary.Read(buf, binary.BigEndian, &m)
	s = string(m)
	return
}

func (m *Reply) Decrypt(key types.EncryptionKey) error {
	if m.IsKRBError {
		return m.KRBError
	}
	err := m.KRBPriv.DecryptEncPart(key)
	if err != nil {
		return err
	}
	m.ResultCode, m.Result = parseResponse(m.KRBPriv.DecryptedEncPart.UserData)
	return nil
}
