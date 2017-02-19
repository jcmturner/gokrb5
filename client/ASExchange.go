package client

import (
	"github.com/jcmturner/gokrb5/messages"
	"fmt"
	"errors"
	"github.com/jcmturner/gokrb5/iana/errorcode"
)

func (cl *Client) ASExchange() error {
	if !cl.IsConfigured() {
		return errors.New("Client is not configured correctly.")
	}
	a := messages.NewASReq(cl.Config, cl.Username)
	b, err := a.Marshal()
	if err != nil {
		return fmt.Errorf("Error marshalling AS_REQ: %v", err)
	}
	rb, err := cl.SendToKDC(b)
	if err != nil {
		return fmt.Errorf("Error sending AS_REQ to KDC: %v", err)
	}
	var ar messages.ASRep
	err = ar.Unmarshal(rb)
	if err != nil {
		//An KRBError may have been returned instead.
		var krberr messages.KRBError
		err = krberr.Unmarshal(rb)
		if err != nil {
			return fmt.Errorf("Could not unmarshal data returned from KDC: %v", err)
		}
		if krberr.ErrorCode = errorcode.KDC_ERR_PREAUTH_REQUIRED {
			//TODO put PA TIMESTAMP here
		}
		return krberr
	}
	if len(cl.Keytab.Entries) > 1 {
		err = ar.DecryptEncPartWithKeytab(cl.Keytab)
		if err != nil {
			return fmt.Errorf("Error decrypting AS_REP encPart with keytab: %v", err)
		}
	} else {
		err = ar.DecryptEncPartWithPassword(cl.Password)
		if err != nil {
			return fmt.Errorf("Error decrypting AS_REP encPart with password: %v", err)
		}
	}
	return nil
}
