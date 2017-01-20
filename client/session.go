package client

import (
	"github.com/jcmturner/gokrb5/types"
	"time"
)

type session struct {
	AuthTime  time.Time
	EndTime   time.Time
	RenewTill time.Time
	//TODO Need to check if this is the TGT
	TGT        types.Ticket
	SessionKey types.EncryptionKey
}
