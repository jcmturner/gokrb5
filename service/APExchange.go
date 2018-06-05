package service

import (
	"fmt"
	"time"

	"gopkg.in/jcmturner/gokrb5.v5/credentials"
	"gopkg.in/jcmturner/gokrb5.v5/iana/errorcode"
	"gopkg.in/jcmturner/gokrb5.v5/iana/flags"
	"gopkg.in/jcmturner/gokrb5.v5/keytab"
	"gopkg.in/jcmturner/gokrb5.v5/krberror"
	"gopkg.in/jcmturner/gokrb5.v5/messages"
	"gopkg.in/jcmturner/gokrb5.v5/types"
)

// ValidateAPREQ validates an AP_REQ sent to the service. Returns a boolean for if the AP_REQ is valid and the client's principal name and realm.
func ValidateAPREQ(APReq messages.APReq, kt keytab.Keytab, sa string, cAddr string, requireHostAddr bool) (bool, credentials.Credentials, error) {
	var creds credentials.Credentials
	err := APReq.Ticket.DecryptEncPart(kt, sa)
	if err != nil {
		return false, creds, krberror.Errorf(err, krberror.DecryptingError, "error decrypting encpart of service ticket provided")
	}
	a, err := APReq.DecryptAuthenticator(APReq.Ticket.DecryptedEncPart.Key)
	if err != nil {
		return false, creds, krberror.Errorf(err, krberror.DecryptingError, "error extracting authenticator")
	}
	// Check CName in Authenticator is the same as that in the ticket
	if !a.CName.Equal(APReq.Ticket.DecryptedEncPart.CName) {
		err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADMATCH, "CName in Authenticator does not match that in service ticket")
		return false, creds, err
	}
	if len(APReq.Ticket.DecryptedEncPart.CAddr) > 0 {
		//The addresses in the ticket (if any) are then
		//searched for an address matching the operating-system reported
		//address of the client.  If no match is found or the server insists on
		//ticket addresses but none are present in the ticket, the
		//KRB_AP_ERR_BADADDR error is returned.
		h, err := types.GetHostAddress(cAddr)
		if err != nil {
			err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADADDR, err.Error())
			return false, creds, err
		}
		if !types.HostAddressesContains(APReq.Ticket.DecryptedEncPart.CAddr, h) {
			err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADADDR, "Client address not within the list contained in the service ticket")
			return false, creds, err
		}
	} else if requireHostAddr {
		err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADADDR, "ticket does not contain HostAddress values required")
		return false, creds, err
	}

	// Check the clock skew between the client and the service server
	ct := a.CTime.Add(time.Duration(a.Cusec) * time.Microsecond)
	t := time.Now().UTC()
	// Hardcode 5 min max skew. May want to make this configurable
	d := time.Duration(5) * time.Minute
	if t.Sub(ct) > d || ct.Sub(t) > d {
		err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_SKEW, fmt.Sprintf("Clock skew with client too large. Greater than %v seconds", d))
		return false, creds, err
	}

	// Check for replay
	rc := GetReplayCache(d)
	if rc.IsReplay(APReq.Ticket.SName, a) {
		err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_REPEAT, "Replay detected")
		return false, creds, err
	}

	// Check for future tickets or invalid tickets
	if APReq.Ticket.DecryptedEncPart.StartTime.Sub(t) > d || types.IsFlagSet(&APReq.Ticket.DecryptedEncPart.Flags, flags.Invalid) {
		err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_TKT_NYV, "Service ticket provided is not yet valid")
		return false, creds, err
	}

	// Check for expired ticket
	if t.Sub(APReq.Ticket.DecryptedEncPart.EndTime) > d {
		err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_TKT_EXPIRED, "Service ticket provided has expired")
		return false, creds, err
	}
	creds = credentials.NewCredentialsFromPrincipal(a.CName, a.CRealm)
	creds.SetAuthTime(t)
	creds.SetAuthenticated(true)
	creds.SetValidUntil(APReq.Ticket.DecryptedEncPart.EndTime)
	isPAC, pac, err := APReq.Ticket.GetPACType(kt, sa)
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
			LogonDomainID:       pac.KerbValidationInfo.LogonDomainID.ToString(),
		})
	}
	return true, creds, nil
}
