package spnego

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"

	"gopkg.in/jcmturner/goidentity.v3"
	"gopkg.in/jcmturner/gokrb5.v6/client"
	"gopkg.in/jcmturner/gokrb5.v6/gssapi"
	"gopkg.in/jcmturner/gokrb5.v6/keytab"
	"gopkg.in/jcmturner/gokrb5.v6/krberror"
	"gopkg.in/jcmturner/gokrb5.v6/service"
	"gopkg.in/jcmturner/gokrb5.v6/types"
)

// Client side functionality //

// SetSPNEGOHeader gets the service ticket and sets it as the SPNEGO authorization header on HTTP request object.
// To auto generate the SPN from the request object pass a null string "".
func SetSPNEGOHeader(cl *client.Client, r *http.Request, spn string) error {
	if spn == "" {
		spn = "HTTP/" + strings.SplitN(r.Host, ":", 2)[0]
	}
	s := SPNEGOClient(cl, spn)
	err := s.AcquireCred()
	if err != nil {
		return fmt.Errorf("could not aquire client credenital: %v", err)
	}
	st, err := s.InitSecContext()
	if err != nil {
		return fmt.Errorf("could not initalize context: %v", err)
	}
	nb, err := st.Marshal()
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "could not marshal SPNEGO")
	}
	hs := "Negotiate " + base64.StdEncoding.EncodeToString(nb)
	r.Header.Set("Authorization", hs)
	return nil
}

// Service side functionality //

type ctxKey string

const (
	// spnegoNegTokenRespKRBAcceptCompleted - The response on successful authentication always has this header. Capturing as const so we don't have marshaling and encoding overhead.
	spnegoNegTokenRespKRBAcceptCompleted = "Negotiate oRQwEqADCgEAoQsGCSqGSIb3EgECAg=="
	// spnegoNegTokenRespReject - The response on a failed authentication always has this rejection header. Capturing as const so we don't have marshaling and encoding overhead.
	spnegoNegTokenRespReject = "Negotiate oQcwBaADCgEC"
	// spnegoNegTokenRespIncompleteKRB5 - Response token specifying incomplete context and KRB5 as the supported mechtype.
	spnegoNegTokenRespIncompleteKRB5 = "Negotiate oRQwEqADCgEBoQsGCSqGSIb3EgECAg=="
	// CTXKeyAuthenticated is the request context key holding a boolean indicating if the request has been authenticated.
	CTXKeyAuthenticated ctxKey = "github.com/jcmturner/gokrb5/CTXKeyAuthenticated"
	// CTXKeyCredentials is the request context key holding the credentials gopkg.in/jcmturner/goidentity.v2/Identity object.
	CTXKeyCredentials ctxKey = "github.com/jcmturner/gokrb5/CTXKeyCredentials"
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
func SPNEGOKRB5Authenticate(inner http.Handler, kt *keytab.Keytab, options ...func(*service.Settings)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := strings.SplitN(r.Header.Get(HTTPHeaderAuthRequest), " ", 2)

		if len(s) != 2 || s[0] != HTTPHeaderAuthResponseValueKey {
			// No Authorization header set so return 401 with WWW-Authenticate Negotiate header
			w.Header().Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
			http.Error(w, UnauthorizedMsg, http.StatusUnauthorized)
			return
		}

		var spnego *SPNEGO
		h, err := types.GetHostAddress(r.RemoteAddr)
		if err == nil {
			// put in this order so that if the user provides a ClientAddress it will override the one here.
			o := append([]func(*service.Settings){service.ClientAddress(h)}, options...)
			spnego = SPNEGOService(kt, o...)
		} else {
			spnego = SPNEGOService(kt, options...)
			if spnego.serviceSettings.Logger() != nil {
				spnego.serviceSettings.Logger().Printf("SPNEGO could not parse client address: %v", err)
			}
		}

		b, err := base64.StdEncoding.DecodeString(s[1])
		if err != nil {
			if spnego.serviceSettings.Logger() != nil {
				spnego.serviceSettings.Logger().Printf("SPNEGO error in base64 decoding negotiation header: %v", err)
			}
			negotiateKRB5MechType(w)
		}
		var st SPNEGOToken
		err = st.Unmarshal(b)
		if err != nil {
			if spnego.serviceSettings.Logger() != nil {
				spnego.serviceSettings.Logger().Printf("SPNEGO error in unmarshaling SPNEGO token: %v", err)
			}
			negotiateKRB5MechType(w)
		}

		authed, ctx, err := spnego.AcceptSecContext(&st)
		if !authed {
			st, ok := err.(gssapi.Status)
			if ok && st.Code == gssapi.StatusContinueNeeded {
				negotiateKRB5MechType(w)
			}
			rejectSPNEGO(w, spnego.serviceSettings.Logger(), fmt.Sprintf("%v - %v", r.RemoteAddr, err))

		}
		if authed {
			id := ctx.Value(CTXKeyCredentials).(goidentity.Identity)
			rctx := r.Context()
			rctx = context.WithValue(rctx, CTXKeyCredentials, id)
			rctx = context.WithValue(rctx, CTXKeyAuthenticated, ctx.Value(CTXKeyAuthenticated))
			if spnego.serviceSettings.Logger() != nil {
				spnego.serviceSettings.Logger().Printf("%v %s@%s - SPNEGO authentication succeeded", r.RemoteAddr, id.UserName(), id.Domain())
			}
			spnegoResponseAcceptCompleted(w)
			inner.ServeHTTP(w, r.WithContext(ctx))
		} else {
			rejectSPNEGO(w, spnego.serviceSettings.Logger(), fmt.Sprintf("%v - SPNEGO Kerberos authentication failed: %v", r.RemoteAddr, err))
		}
		return
	})
}

func negotiateKRB5MechType(w http.ResponseWriter) {
	w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespIncompleteKRB5)
	http.Error(w, UnauthorizedMsg, http.StatusUnauthorized)
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
	http.Error(w, UnauthorizedMsg, http.StatusUnauthorized)
}

func spnegoResponseAcceptCompleted(w http.ResponseWriter) {
	w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespKRBAcceptCompleted)
}
