package service

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// POTENTIAL BREAKING CHANGE notice. Context keys used will change to a name-spaced strings to avoid clashes.
// If you are using the constants service.CTXKeyAuthenticated and service.CTXKeyCredentials
// defined below when retrieving data from the request context your code will be unaffected.
// However if, for example, you are retrieving context like this: r.Context().Value(1) then
// you will need to update to replace the 1 with service.CTXKeyCredentials.
type ctxKey int

const (
	// spnegoNegTokenRespKRBAcceptCompleted - The response on successful authentication always has this header. Capturing as const so we don't have marshaling and encoding overhead.
	spnegoNegTokenRespKRBAcceptCompleted = "Negotiate oRQwEqADCgEAoQsGCSqGSIb3EgECAg=="
	// spnegoNegTokenRespReject - The response on a failed authentication always has this rejection header. Capturing as const so we don't have marshaling and encoding overhead.
	spnegoNegTokenRespReject = "Negotiate oQcwBaADCgEC"
	// CTXKeyAuthenticated is the request context key holding a boolean indicating if the request has been authenticated.
	CTXKeyAuthenticated ctxKey = 0
	// CTXKeyCredentials is the request context key holding the credentials gopkg.in/jcmturner/goidentity.v2/Identity object.
	CTXKeyCredentials ctxKey = 1
	// HTTPHeaderAuthRequest is the header that will hold authn/z information.
	HTTPHeaderAuthRequest = "Authorization"
	// HTTPHeaderAuthResponse is the header that will hold SPNEGO data from the server.
	HTTPHeaderAuthResponse = "WWW-Authenticate"
	// HTTPHeaderAuthResponseValueKey is the key in the auth header for SPNEGO.
	HTTPHeaderAuthResponseValueKey = "Negotiate"
	// UnauthorizedMsg is the message returned in the body when authentication fails.
	UnauthorizedMsg = "Unauthorised.\n"
)

// SPNEGOKRB5Authenticate is a Kerberos SPNEGO authentication HTTP handler wrapper.
func SPNEGOKRB5Authenticate(f http.Handler, c *Config, l *log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := strings.SplitN(r.Header.Get(HTTPHeaderAuthRequest), " ", 2)
		if len(s) != 2 || s[0] != HTTPHeaderAuthResponseValueKey {
			w.Header().Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
			w.WriteHeader(401)
			w.Write([]byte(UnauthorizedMsg))
			return
		}
		id, authned, err := c.Authenticate(s[1], r.RemoteAddr)
		if err != nil {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - %v", r.RemoteAddr, err))
			return
		}
		if authned {
			ctx := r.Context()
			ctx = context.WithValue(ctx, CTXKeyCredentials, id)
			ctx = context.WithValue(ctx, CTXKeyAuthenticated, true)
			if l != nil {
				l.Printf("%v %s@%s - SPNEGO authentication succeeded", r.RemoteAddr, id.UserName(), id.Domain())
			}
			spnegoResponseAcceptCompleted(w)
			f.ServeHTTP(w, r.WithContext(ctx))
		} else {
			rejectSPNEGO(w, l, fmt.Sprintf("%v - SPNEGO Kerberos authentication failed: %v", r.RemoteAddr, err))
			return
		}
		return
	})
}

// Set the headers for a rejected SPNEGO negotiation and return an unauthorized status code.
func rejectSPNEGO(w http.ResponseWriter, l *log.Logger, logMsg string) {
	if l != nil {
		l.Println(logMsg)
	}
	spnegoResponseReject(w)
}

func spnegoResponseReject(w http.ResponseWriter) {
	w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespReject)
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(UnauthorizedMsg))
}

func spnegoResponseAcceptCompleted(w http.ResponseWriter) {
	w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespKRBAcceptCompleted)
}
