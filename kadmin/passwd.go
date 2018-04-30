package kadmin

import (
	"gopkg.in/jcmturner/gokrb5.v4/crypto"
	"gopkg.in/jcmturner/gokrb5.v4/krberror"
	"gopkg.in/jcmturner/gokrb5.v4/messages"
	"gopkg.in/jcmturner/gokrb5.v4/types"
)

const (
	spn = "kadmin/changepw@%s"
)

func ChangePasswdMsg(cname types.PrincipalName, realm, password string, tkt messages.Ticket, sessionKey types.EncryptionKey) (Message, error) {
	// Create change password data struct and marshal to bytes
	chgpasswd := ChangePasswdData{
		NewPasswd: []byte(password),
		TargName:  cname,
		TargRealm: realm,
	}
	chpwdb, err := chgpasswd.Marshal()
	if err != nil {
		return Message{}, krberror.Errorf(err, krberror.KRBMsgError, "error marshaling change passwd data")
	}

	// Generate authenticator
	auth, err := types.NewAuthenticator(realm, cname)
	if err != nil {
		return Message{}, krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")
	}
	etype, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return Message{}, krberror.Errorf(err, krberror.KRBMsgError, "error generating subkey etype")
	}
	err = auth.GenerateSeqNumberAndSubKey(sessionKey.KeyType, etype.GetKeyByteSize())
	if err != nil {
		return Message{}, krberror.Errorf(err, krberror.KRBMsgError, "error generating subkey")
	}

	// Generate AP_REQ
	APreq, err := messages.NewAPReq(tkt, sessionKey, auth)
	if err != nil {
		return Message{}, err
	}

	// Form the KRBPriv encpart data
	//TODO set the SAddress field???
	kp := messages.EncKrbPrivPart{
		Timestamp:      auth.CTime,
		Usec:           auth.Cusec,
		SequenceNumber: auth.SeqNumber,
	}
	_, kp.UserData, err = etype.EncryptData(auth.SubKey.KeyValue, chpwdb)
	if err != nil {
		return Message{}, krberror.Errorf(err, krberror.EncryptingError, "error encrypting change passwd data")
	}

	return Message{
		APREQ:   APreq,
		KRBPriv: messages.NewKRBPriv(kp),
	}, nil
}
