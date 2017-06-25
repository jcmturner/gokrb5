package client

import (
	"errors"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/iana/errorcode"
	"github.com/jcmturner/gokrb5/iana/keyusage"
	"github.com/jcmturner/gokrb5/iana/patype"
	"github.com/jcmturner/gokrb5/krberror"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/types"
	"sort"
)

// ASExchange performs an AS exchange for the client to retrieve a TGT.
func (cl *Client) ASExchange() error {
	if !cl.IsConfigured() {
		return errors.New("Client is not configured correctly")
	}
	ASReq := messages.NewASReq(cl.Config, cl.Credentials.CName)
	err := setPAData(cl, &ASReq)
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMSG_ERROR, "AS Exchange Error: failed setting AS_REQ PAData")
	}
	b, err := ASReq.Marshal()
	if err != nil {
		return krberror.Errorf(err, krberror.ENCODING_ERROR, "AS Exchange Error: failed marshaling AS_REQ")
	}

	var ASRep messages.ASRep

	rb, err := cl.SendToKDC(b)
	if err != nil {
		if e, ok := err.(messages.KRBError); ok && e.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED {
			// From now on assume this client will need to do this pre-auth and set the PAData
			cl.GoKrb5Conf.Assume_PA_ENC_TIMESTAMP_Required = true
			err = setPAData(cl, &ASReq)
			if err != nil {
				return krberror.Errorf(err, krberror.KRBMSG_ERROR, "AS Exchange Error: failed setting AS_REQ PAData for pre-authentication required")
			}
			b, err := ASReq.Marshal()
			if err != nil {
				return krberror.Errorf(err, krberror.ENCODING_ERROR, "AS Exchange Error: failed marshaling AS_REQ with PAData")
			}
			rb, err = cl.SendToKDC(b)
			if err != nil {
				return krberror.Errorf(err, krberror.NETWORKING_ERROR, "AS Exchange Error: failed sending AS_REQ to KDC")
			}
		} else {
			return krberror.Errorf(err, krberror.NETWORKING_ERROR, "AS Exchange Error: failed sending AS_REQ to KDC")
		}
	}
	err = ASRep.Unmarshal(rb)
	if err != nil {
		return krberror.Errorf(err, krberror.ENCODING_ERROR, "AS Exchange Error: failed to process the AS_REP")
	}
	if ok, err := ASRep.IsValid(cl.Config, cl.Credentials, ASReq); !ok {
		return krberror.Errorf(err, krberror.KRBMSG_ERROR, "AS Exchange Error: AS_REP is not valid")
	}
	cl.session = &session{
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
			return krberror.Errorf(err, krberror.KRBMSG_ERROR, "Error creating PAEncTSEnc for Pre-Authentication")
		}
		sort.Sort(sort.Reverse(sort.IntSlice(cl.Config.LibDefaults.Default_tkt_enctype_ids)))
		etype, err := crypto.GetEtype(cl.Config.LibDefaults.Default_tkt_enctype_ids[0])
		if err != nil {
			return krberror.Errorf(err, krberror.ENCRYPTING_ERROR, "Error creating etype")
		}
		key, err := cl.Credentials.Keytab.GetEncryptionKey(cl.Credentials.CName.NameString, cl.Config.LibDefaults.Default_realm, 1, etype.GetETypeID())
		if err != nil {
			return krberror.Errorf(err, krberror.ENCRYPTING_ERROR, "Error getting key from keytab in credentials")
		}
		paEncTS, err := crypto.GetEncryptedData(paTSb, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP, 1)
		if err != nil {
			return krberror.Errorf(err, krberror.ENCRYPTING_ERROR, "Error encrypting pre-authentication timestamp")
		}
		pb, err := paEncTS.Marshal()
		if err != nil {
			return krberror.Errorf(err, krberror.ENCODING_ERROR, "Error marshaling the PAEncTSEnc encrypted data")
		}
		pa := types.PAData{
			PADataType:  patype.PA_ENC_TIMESTAMP,
			PADataValue: pb,
		}
		ASReq.PAData = append(ASReq.PAData, pa)
	}
	return nil
}
