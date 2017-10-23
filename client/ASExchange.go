package client

import (
	"gopkg.in/jcmturner/gokrb5.v1/crypto"
	"gopkg.in/jcmturner/gokrb5.v1/iana/errorcode"
	"gopkg.in/jcmturner/gokrb5.v1/iana/keyusage"
	"gopkg.in/jcmturner/gokrb5.v1/iana/patype"
	"gopkg.in/jcmturner/gokrb5.v1/krberror"
	"gopkg.in/jcmturner/gokrb5.v1/messages"
	"gopkg.in/jcmturner/gokrb5.v1/types"
	"sort"
)

// ASExchange performs an AS exchange for the client to retrieve a TGT.
func (cl *Client) ASExchange(realm string, referral int) error {
	if ok, err := cl.IsConfigured(); !ok {
		return krberror.Errorf(err, krberror.ConfigError, "AS Exchange cannot be preformed")
	}
	ASReq, err := messages.NewASReq(realm, cl.Config, cl.Credentials.CName)
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "Error generating new AS_REQ")
	}
	err = setPAData(cl, messages.KRBError{}, &ASReq)
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting AS_REQ PAData")
	}
	b, err := ASReq.Marshal()
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling AS_REQ")
	}

	var ASRep messages.ASRep

	rb, err := cl.SendToKDC(b, realm)
	if err != nil {
		if e, ok := err.(messages.KRBError); ok {
			switch e.ErrorCode {
			case errorcode.KDC_ERR_PREAUTH_REQUIRED:
				// From now on assume this client will need to do this pre-auth and set the PAData
				cl.GoKrb5Conf.AssumePAEncTimestampRequired = true
				err = setPAData(cl, e, &ASReq)
				if err != nil {
					return krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting AS_REQ PAData for pre-authentication required")
				}
				b, err := ASReq.Marshal()
				if err != nil {
					return krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling AS_REQ with PAData")
				}
				rb, err = cl.SendToKDC(b, realm)
				if err != nil {
					return krberror.Errorf(err, krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC")
				}
			case errorcode.KDC_ERR_WRONG_REALM:
				// Client referral https://tools.ietf.org/html/rfc6806.html#section-7
				if referral > 5 {
					return krberror.Errorf(err, krberror.KRBMsgError, "maximum number of client referrals exceeded")
				}
				referral += 1
				return cl.ASExchange(e.CRealm, referral)
			}
		} else {
			return krberror.Errorf(err, krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC")
		}
	}
	err = ASRep.Unmarshal(rb)
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed to process the AS_REP")
	}
	if ok, err := ASRep.IsValid(cl.Config, cl.Credentials, ASReq); !ok {
		return krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: AS_REP is not valid")
	}
	cl.AddSession(ASRep.Ticket, ASRep.DecryptedEncPart)
	return nil
}

func setPAData(cl *Client, krberr messages.KRBError, ASReq *messages.ASReq) error {
	if !cl.GoKrb5Conf.DisablePAFXFast {
		pa := types.PAData{PADataType: patype.PA_REQ_ENC_PA_REP}
		ASReq.PAData = append(ASReq.PAData, pa)
	}
	if cl.GoKrb5Conf.AssumePAEncTimestampRequired {
		paTSb, err := types.GetPAEncTSEncAsnMarshalled()
		if err != nil {
			return krberror.Errorf(err, krberror.KRBMsgError, "Error creating PAEncTSEnc for Pre-Authentication")
		}
		sort.Sort(sort.Reverse(sort.IntSlice(cl.Config.LibDefaults.DefaultTktEnctypeIDs)))
		etype, err := crypto.GetEtype(cl.Config.LibDefaults.DefaultTktEnctypeIDs[0])
		if err != nil {
			return krberror.Errorf(err, krberror.EncryptingError, "Error creating etype")
		}
		key, err := cl.Key(etype, krberr)
		if err != nil {
			return krberror.Errorf(err, krberror.EncryptingError, "Error getting key from credentials")
		}
		paEncTS, err := crypto.GetEncryptedData(paTSb, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP, 1)
		if err != nil {
			return krberror.Errorf(err, krberror.EncryptingError, "Error encrypting pre-authentication timestamp")
		}
		pb, err := paEncTS.Marshal()
		if err != nil {
			return krberror.Errorf(err, krberror.EncodingError, "Error marshaling the PAEncTSEnc encrypted data")
		}
		pa := types.PAData{
			PADataType:  patype.PA_ENC_TIMESTAMP,
			PADataValue: pb,
		}
		ASReq.PAData = append(ASReq.PAData, pa)
	}
	return nil
}
