package mstypes

import (
	"encoding/binary"
	"github.com/jcmturner/gokrb5/ndr"
)

type CypherBlock struct {
	Data []byte // size = 8
}

type UserSessionKey struct {
	Data []CypherBlock // size = 2
}

func Read_UserSessionKey(b *[]byte, p *int, e *binary.ByteOrder) UserSessionKey {
	cb1 := CypherBlock{
		Data: ndr.Read_bytes(b, p, 8, e),
	}
	cb2 := CypherBlock{
		Data: ndr.Read_bytes(b, p, 8, e),
	}
	return UserSessionKey{
		Data: []CypherBlock{cb1, cb2},
	}
}
