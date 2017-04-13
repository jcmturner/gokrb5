package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/jcmturner/gokrb5/GSSAPI"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/iana/errorcode"
	"github.com/jcmturner/gokrb5/iana/keyusage"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/types"
	"log"
	"net/http"
	"strings"
	"time"
	"net"
)

const (
	// The response on successful authentication always has this header. Capturing as const so we don't have marshaling and encoding overhead.
	SPNEGO_NegTokenResp_Krb_Accept_Completed = "Negotiate oRQwEqADCgEAoQsGCSqGSIb3EgECAg=="
	// The response on a failed authentication always has this rejection header. Capturing as const so we don't have marshaling and encoding overhead.
	SPNEGO_NegTokenResp_Reject               = "Negotiate oQcwBaADCgEC"
)

// Kerberos SPNEGO authentication HTTP handler wrapper.
func SPNEGOKRB5Authenticate(f http.Handler, ktab keytab.Keytab, l *log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(s) != 2 || s[0] != "Negotiate" {
			w.Header().Set("WWW-Authenticate", "Negotiate")
			w.WriteHeader(401)
			w.Write([]byte("Unauthorised.\n"))
			return
		}
		b, err := base64.StdEncoding.DecodeString(s[1])
		if err != nil {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO error in base64 decoding negotiation header: %v", r.RemoteAddr, err))
			return
		}
		var spnego GSSAPI.SPNEGO
		err = spnego.Unmarshal(b)
		if !spnego.Init {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO negotiation token is not a NegTokenInit: %v", r.RemoteAddr, err))
			return
		}
		if !spnego.NegTokenInit.MechTypes[0].Equal(GSSAPI.MechTypeOID_Krb5) {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO OID of MechToken is not of type KRB5", r.RemoteAddr))
			return
		}
		var mt GSSAPI.MechToken
		err = mt.Unmarshal(spnego.NegTokenInit.MechToken)
		if err != nil {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO error unmarshaling MechToken: %v", r.RemoteAddr, err))
			return
		}
		if !mt.IsAPReq() {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - MechToken does not contain an AP_REQ - KRB_AP_ERR_MSG_TYPE", r.RemoteAddr))
			return
		}
		err = mt.APReq.Ticket.DecryptEncPart(ktab)
		if err != nil {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO error decrypting the service ticket provided: %v", r.RemoteAddr, err))
			return
		}
		ab, err := crypto.DecryptEncPart(mt.APReq.Authenticator, mt.APReq.Ticket.DecryptedEncPart.Key, keyusage.AP_REQ_AUTHENTICATOR)
		if err != nil {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO error decrypting the authenticator provided: %v", r.RemoteAddr, err))
			return
		}
		var a types.Authenticator
		err = a.Unmarshal(ab)
		if err != nil {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO error unmarshalling the authenticator: %v", r.RemoteAddr, err))
			return
		}
		if ok, err := validateAPREQ(a, mt.APReq, r); ok {
			cnameStr := a.CName.GetPrincipalNameString()
			ctx := r.Context()
			ctx = context.WithValue(ctx, "cname", cnameStr)
			ctx = context.WithValue(ctx, "crealm", a.CRealm)
			ctx = context.WithValue(ctx, "authenticated", true)
			if l != nil {
				l.Printf("%v %s@%s - SPNEGO authentication succeeded", r.RemoteAddr, cnameStr, a.CRealm)
			}
			w.Header().Set("WWW-Authenticate", SPNEGO_NegTokenResp_Krb_Accept_Completed)
			f.ServeHTTP(w, r.WithContext(ctx))
		} else {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO Kerberos authentication failed: %v", r.RemoteAddr, err))
			return
		}
	})
}

// Validate the AP_REQ provided in the SPNEGO NegTokenInit.
func validateAPREQ(a types.Authenticator, APReq messages.APReq, r *http.Request) (bool, error) {
	// Check CName in Authenticator is the same as that in the ticket
	if !a.CName.Equal(APReq.Ticket.DecryptedEncPart.CName) {
		err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADMATCH, "CName in Authenticator does not match that in service ticket")
		return false, err
	}
	if len(APReq.Ticket.DecryptedEncPart.CAddr) > 0 {
		//The addresses in the ticket (if any) are then
		//searched for an address matching the operating-system reported
		//address of the client.  If no match is found or the server insists on
		//ticket addresses but none are present in the ticket, the
		//KRB_AP_ERR_BADADDR error is returned.
		cAddr, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADADDR, "Invalid format of client address.")
			return false, err
		}
		ip := net.ParseIP(cAddr)
		hb, err := ip.MarshalText()
		if err != nil {
			err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADADDR, "Could not marshal client's address into bytes.")
			return false, err
		}
		var ht int
		if ip.To4() != nil {
			ht = types.AddrType_IPv4
		} else if ip.To16() != nil {
			ht = types.AddrType_IPv6
		} else {
			err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADADDR, "Could not determine client's address type.")
			return false, err
		}
		h := types.HostAddress{
			AddrType: ht,
			Address: hb,
		}
		if !types.HostAddressesContains(APReq.Ticket.DecryptedEncPart.CAddr, h) {
			err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADADDR, "Client address not within the list contained in the service ticket")
			return false, err
		}
	}

	// Check the clock skew between the client and the service server
	ct := a.CTime.Add(time.Duration(a.Cusec) * time.Microsecond)
	t := time.Now().UTC()
	// Hardcode 5 min max skew. May want to make this configurable
	d := time.Duration(5) * time.Minute
	if t.Sub(ct) > d || ct.Sub(t) > d {
		err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_SKEW, fmt.Sprintf("Clock skew with client too large. Greater than %v seconds", d))
		return false, err
	}

	// Check for replay
	rc := GetReplayCache(d)
	if rc.IsReplay(d, APReq.Ticket.SName, a) {
		err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_REPEAT, "Replay detected")
		return false, err
	}

	// Check for future tickets or invalid tickets
	if APReq.Ticket.DecryptedEncPart.StartTime.Sub(t) > d || types.IsFlagSet(&APReq.Ticket.DecryptedEncPart.Flags, types.Invalid) {
		err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_TKT_NYV, "Service ticket provided is not yet valid")
		return false, err
	}

	// Check for expired ticket
	if t.Sub(APReq.Ticket.DecryptedEncPart.EndTime) > d {
		err := messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_TKT_EXPIRED, "Service ticket provided has expired")
		return false, err
	}
	return true, nil
}

// Set the headers for a rejected SPNEGO negotiation and return an unauthorized status code.
func rejectSPNEGO(w http.ResponseWriter, l *log.Logger, logMsg string) {
	if l != nil {
		l.Println(logMsg)
	}
	w.Header().Set("WWW-Authenticate", SPNEGO_NegTokenResp_Reject)
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte("Unauthorised.\n"))
}
