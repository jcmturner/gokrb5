package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/jcmturner/gokrb5/GSSAPI"
	"github.com/jcmturner/gokrb5/keytab"
	"log"
	"net/http"
	"strings"
)

const (
	// The response on successful authentication always has this header. Capturing as const so we don't have marshaling and encoding overhead.
	SPNEGO_NegTokenResp_Krb_Accept_Completed = "Negotiate oRQwEqADCgEAoQsGCSqGSIb3EgECAg=="
	// The response on a failed authentication always has this rejection header. Capturing as const so we don't have marshaling and encoding overhead.
	SPNEGO_NegTokenResp_Reject = "Negotiate oQcwBaADCgEC"
)

// Kerberos SPNEGO authentication HTTP handler wrapper.
func SPNEGOKRB5Authenticate(f http.Handler, kt keytab.Keytab, l *log.Logger) http.Handler {
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

		if ok, creds, err := ValidateAPREQ(mt.APReq, kt, r.RemoteAddr); ok {
			ctx := r.Context()
			ctx = context.WithValue(ctx, "credentials", creds)
			ctx = context.WithValue(ctx, "authenticated", true)
			if l != nil {
				l.Printf("%v %s@%s - SPNEGO authentication succeeded", r.RemoteAddr, creds.Username, creds.Realm)
			}
			w.Header().Set("WWW-Authenticate", SPNEGO_NegTokenResp_Krb_Accept_Completed)
			f.ServeHTTP(w, r.WithContext(ctx))
		} else {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO Kerberos authentication failed: %v", r.RemoteAddr, err))
			return
		}
	})
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
