package client

import (
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/iana/errorcode"
	"github.com/jcmturner/gokrb5/iana/keyusage"
	"github.com/jcmturner/gokrb5/iana/patype"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/types"
	"sort"
)

// Perform an AS exchange for the client to retrieve a TGT.
func (cl *Client) ASExchange() error {
	if !cl.IsConfigured() {
		return errors.New("Client is not configured correctly.")
	}
	ASReq := messages.NewASReq(cl.Config, cl.Credentials.CName)
	err := setPAData(cl, &ASReq)
	if err != nil {
		return fmt.Errorf("Error setting AS_REQ PAData: %v", err)
	}
	b, err := ASReq.Marshal()
	if err != nil {
		return fmt.Errorf("Error marshalling AS_REQ: %v", err)
	}

	var ASRep messages.ASRep

	rb, err := cl.SendToKDC(b)
	if err != nil {
		if e, ok := err.(messages.KRBError); ok && e.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED {
			// From now on assume this client will need to do this pre-auth and set the PAData
			cl.GoKrb5Conf.Assume_PA_ENC_TIMESTAMP_Required = true
			err = setPAData(cl, &ASReq)
			if err != nil {
				return fmt.Errorf("Error setting AS_REQ PAData for pre-authentication required: %v", err)
			}
			b, err := ASReq.Marshal()
			if err != nil {
				return fmt.Errorf("Error marshalling AS_REQ with PAData: %v", err)
			}
			rb, err = cl.SendToKDC(b)
			if err != nil {
				return fmt.Errorf("Error sending AS_REQ to KDC: %v", err)
			}
		} else {
			return fmt.Errorf("Error sending AS_REQ to KDC: %v", err)
		}
	}
	err = ASRep.Unmarshal(rb)
	if err != nil {
		return fmt.Errorf("Could not unmarshal AS_REP data returned from KDC: %v", err)
	}
	if ok, err := ASRep.IsValid(cl.Config, cl.Credentials, ASReq); !ok {
		return fmt.Errorf("AS_REP is not valid: %v", err)
	}
	cl.Session = &Session{
		AuthTime:             ASRep.DecryptedEncPart.AuthTime,
		EndTime:              ASRep.DecryptedEncPart.EndTime,
		RenewTill:            ASRep.DecryptedEncPart.RenewTill,
		TGT:                  ASRep.Ticket,
		SessionKey:           ASRep.DecryptedEncPart.Key,
		SessionKeyExpiration: ASRep.DecryptedEncPart.KeyExpiration,
	}
	return nil
}

func setPAData(cl *Client, ASReq *messages.ASReq) error {
	if !cl.GoKrb5Conf.Disable_PA_FX_FAST {
		pa := types.PAData{PADataType: patype.PA_REQ_ENC_PA_REP}
		ASReq.PAData = append(ASReq.PAData, pa)
	}
	if cl.GoKrb5Conf.Assume_PA_ENC_TIMESTAMP_Required {
		paTSb, err := types.GetPAEncTSEncAsnMarshalled()
		if err != nil {
			return fmt.Errorf("Error creating PAEncTSEnc for Pre-Authentication: %v", err)
		}
		sort.Sort(sort.Reverse(sort.IntSlice(cl.Config.LibDefaults.Default_tkt_enctype_ids)))
		etype, err := crypto.GetEtype(cl.Config.LibDefaults.Default_tkt_enctype_ids[0])
		if err != nil {
			return fmt.Errorf("Error creating etype: %v", err)
		}
		key, err := cl.Credentials.Keytab.GetEncryptionKey(cl.Credentials.CName.NameString, cl.Config.LibDefaults.Default_realm, 1, etype.GetETypeID())
		if err != nil {
			return fmt.Errorf("Error getting key from keytab in credentials: %v", err)
		}
		paEncTS, err := crypto.GetEncryptedData(paTSb, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP, 1)
		if err != nil {
			return fmt.Errorf("Error encrypting pre-authentication timestamp: %v", err)
		}
		pb, err := paEncTS.Marshal()
		if err != nil {
			return fmt.Errorf("Error marshaling the PAEncTSEnc encrypted data: %v", err)
		}
		pa := types.PAData{
			PADataType:  patype.PA_ENC_TIMESTAMP,
			PADataValue: pb,
		}
		ASReq.PAData = append(ASReq.PAData, pa)
	}
	return nil
}
