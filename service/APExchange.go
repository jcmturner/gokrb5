package service

import (
	"fmt"
	"github.com/jcmturner/gokrb5/credentials"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/iana/errorcode"
	"github.com/jcmturner/gokrb5/iana/flags"
	"github.com/jcmturner/gokrb5/iana/keyusage"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/types"
	"time"
)

// Validates an AP_REQ sent to the service. Returns a boolean for if the AP_REQ is valid and the client's principal name and realm.
func ValidateAPREQ(APReq messages.APReq, kt keytab.Keytab, sa string, cAddr string) (bool, credentials.Credentials, error) {
	var creds credentials.Credentials
	err := APReq.Ticket.DecryptEncPart(kt, sa)
	if err != nil {
		return false, creds, fmt.Errorf("Error decrypting encpart of service ticket provided: %v", err)
	}
	ab, err := crypto.DecryptEncPart(APReq.Authenticator, APReq.Ticket.DecryptedEncPart.Key, keyusage.AP_REQ_AUTHENTICATOR)
	if err != nil {
		return false, creds, fmt.Errorf("Error decrypting authenticator: %v", err)
	}
	var a types.Authenticator
	err = a.Unmarshal(ab)
	if err != nil {
		return false, creds, fmt.Errorf("Error unmarshaling authenticator: %v", err)
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
	isPAC, pac, err := APReq.Ticket.GetPACType(kt, sa)
	if isPAC && err != nil {
		return false, creds, err
	}
	if isPAC {
		// There is a valid PAC. Adding attributes to creds
		creds.Attributes["groupMembershipSIDs"] = pac.KerbValidationInfo.GetGroupMembershipSIDs()
		creds.Attributes["logOnTime"] = pac.KerbValidationInfo.LogOnTime.Time()
		creds.Attributes["logOffTime"] = pac.KerbValidationInfo.LogOffTime.Time()
		creds.Attributes["passwordLastSet"] = pac.KerbValidationInfo.PasswordLastSet.Time()
		creds.Attributes["effectiveName"] = pac.KerbValidationInfo.EffectiveName.Value
		creds.Attributes["fullName"] = pac.KerbValidationInfo.FullName.Value
		creds.Attributes["userID"] = int(pac.KerbValidationInfo.UserID)
		creds.Attributes["primaryGroupID"] = int(pac.KerbValidationInfo.PrimaryGroupID)
		creds.Attributes["logonServer"] = pac.KerbValidationInfo.LogonServer.Value
		creds.Attributes["logonDomainName"] = pac.KerbValidationInfo.LogonDomainName.Value
		creds.Attributes["logonDomainID"] = pac.KerbValidationInfo.LogonDomainID.ToString()
	}
	return true, creds, nil
}
