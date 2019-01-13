package service

import (
	"time"

	"gopkg.in/jcmturner/gokrb5.v6/credentials"
	"gopkg.in/jcmturner/gokrb5.v6/iana/errorcode"
	"gopkg.in/jcmturner/gokrb5.v6/messages"
)

// ValidateAPREQ validates an AP_REQ sent to the service. Returns a boolean for if the AP_REQ is valid and the client's principal name and realm.
func ValidateAPREQ(APReq messages.APReq, s *Settings) (bool, *credentials.Credentials, error) {
	var creds *credentials.Credentials

	// Hardcode 5 min max skew. May want to make this configurable
	d := time.Duration(5) * time.Minute

	ok, err := APReq.Verify(s.Keytab, s.spn.GetPrincipalNameString(), d, s.cAddr)
	if err != nil || !ok {
		return false, creds, err
	}

	if s.RequireHostAddr() && len(APReq.Ticket.DecryptedEncPart.CAddr) < 1 {
		return false, creds,
			messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADADDR, "ticket does not contain HostAddress values required")
	}

	// Check for replay
	rc := GetReplayCache(d)
	if rc.IsReplay(APReq.Ticket.SName, APReq.Authenticator) {
		return false, creds,
			messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_REPEAT, "replay detected")
	}

	c := credentials.NewCredentialsFromPrincipal(APReq.Authenticator.CName, APReq.Authenticator.CRealm)
	creds = &c
	creds.SetAuthTime(time.Now().UTC())
	creds.SetAuthenticated(true)
	creds.SetValidUntil(APReq.Ticket.DecryptedEncPart.EndTime)

	//PAC decoding
	if !s.disablePACDecoding {
		isPAC, pac, err := APReq.Ticket.GetPACType(*s.Keytab, s.spn.GetPrincipalNameString())
		if isPAC && err != nil {
			return false, creds, err
		}
		if isPAC {
			// There is a valid PAC. Adding attributes to creds
			creds.SetADCredentials(credentials.ADCredentials{
				GroupMembershipSIDs: pac.KerbValidationInfo.GetGroupMembershipSIDs(),
				LogOnTime:           pac.KerbValidationInfo.LogOnTime.Time(),
				LogOffTime:          pac.KerbValidationInfo.LogOffTime.Time(),
				PasswordLastSet:     pac.KerbValidationInfo.PasswordLastSet.Time(),
				EffectiveName:       pac.KerbValidationInfo.EffectiveName.Value,
				FullName:            pac.KerbValidationInfo.FullName.Value,
				UserID:              int(pac.KerbValidationInfo.UserID),
				PrimaryGroupID:      int(pac.KerbValidationInfo.PrimaryGroupID),
				LogonServer:         pac.KerbValidationInfo.LogonServer.Value,
				LogonDomainName:     pac.KerbValidationInfo.LogonDomainName.Value,
				LogonDomainID:       pac.KerbValidationInfo.LogonDomainID.String(),
			})
		}
	}
	return true, creds, nil
}
