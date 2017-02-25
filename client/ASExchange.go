package client

import (
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/iana/errorcode"
	"github.com/jcmturner/gokrb5/iana/patype"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/types"
	"os"
	"sort"
)

func (cl *Client) Login() error {
	return cl.ASExchange()
}

func (cl *Client) ASExchange() error {
	if !cl.IsConfigured() {
		return errors.New("Client is not configured correctly.")
	}
	a := messages.NewASReq(cl.Config, cl.Credentials.Username)
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
		if krberr.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED {
			paTSb, err := types.GetPAEncTSEncAsnMarshalled()
			if err != nil {
				return fmt.Errorf("Error creating PAEncTSEnc for Pre-Authentication: %v", err)
			}
			sort.Sort(sort.Reverse(sort.IntSlice(cl.Config.LibDefaults.Default_tkt_enctype_ids)))
			etype, err := crypto.GetEtype(cl.Config.LibDefaults.Default_tkt_enctype_ids[0])
			if err != nil {
				return fmt.Errorf("Error creating etype: %v", err)
			}
			paEncTS, err := crypto.GetEncryptedData(paTSb, etype, cl.Config.LibDefaults.Default_realm, cl.Credentials.Username, cl.Credentials.Keytab, 1)
			if err != nil {
				return fmt.Errorf("Error encrypting pre-authentication timestamp: %v", err)
			}
			pa := types.PAData{
				PADataType:  patype.PA_ENC_TIMESTAMP,
				PADataValue: paEncTS,
			}
			a.PAData = append(a.PAData, pa)
			b, err := a.Marshal()
			if err != nil {
				return fmt.Errorf("Error marshalling AS_REQ: %v", err)
			}
			rb, err := cl.SendToKDC(b)
			if err != nil {
				return fmt.Errorf("Error sending AS_REQ to KDC: %v", err)
			}
			err = ar.Unmarshal(rb)
			if err != nil {
				return fmt.Errorf("Could not unmarshal data returned from KDC: %v", err)
			}
		}
		return krberr
	}
	err = ar.DecryptEncPart(cl.Credentials)
	if err != nil {
		return fmt.Errorf("Error decrypting EncPart of AS_REP: %v", err)
	}
	if ok, err := ar.IsValid(cl.Config, a); !ok {
		return fmt.Errorf("AS_REQ is not valid: %v", err)
	}
	cl.Session = Session{
		AuthTime:             ar.DecryptedEncPart.AuthTime,
		EndTime:              ar.DecryptedEncPart.EndTime,
		RenewTill:            ar.DecryptedEncPart.RenewTill,
		TGT:                  ar.Ticket,
		SessionKey:           ar.DecryptedEncPart.Key,
		SessionKeyExpiration: ar.DecryptedEncPart.KeyExpiration,
	}
	return nil
}
