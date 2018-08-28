package service

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	goidentity "gopkg.in/jcmturner/goidentity.v3"
	"gopkg.in/jcmturner/gokrb5.v6/client"
	"gopkg.in/jcmturner/gokrb5.v6/config"
	"gopkg.in/jcmturner/gokrb5.v6/credentials"
	"gopkg.in/jcmturner/gokrb5.v6/gssapi"
	"gopkg.in/jcmturner/gokrb5.v6/keytab"
)

// SPNEGOAuthenticator implements gopkg.in/jcmturner/goidentity.v3.Authenticator interface
type SPNEGOAuthenticator struct {
	SPNEGOHeaderValue string
	ClientAddr        string
	Config            *Config
}

// Config for service side implementation
//
// Keytab (mandatory) - keytab for the service user
//
// KeytabPrincipal (optional) - keytab principal override for the service.
// The service looks for this principal in the keytab to use to decrypt tickets.
// If "" is passed as KeytabPrincipal then the principal will be automatically derived
// from the service name (SName) and realm in the ticket the service is trying to decrypt.
// This is often sufficient if you create the SPN in MIT KDC with: /usr/sbin/kadmin.local -q "add_principal HTTP/<fqdn>"
// When Active Directory is used for the KDC this may need to be the account name you have set the SPN against
// (setspn.exe -a "HTTP/<fqdn>" <account name>)
// If you are unsure run:
//
// klist -k <service's keytab file>
//
// and use the value from the Principal column for the keytab entry the service should use.
//
// RequireHostAddr - require that the kerberos ticket must include client host IP addresses and one must match the client making the request.
// This is controled in the client config with the noaddresses option (http://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html).
//
// DisablePACDecoding - if set to true decoding of the Microsoft PAC will be disabled.
type Config struct {
	Keytab             keytab.Keytab
	ServicePrincipal   string
	RequireHostAddr    bool
	DisablePACDecoding bool
}

func NewSPNEGOAuthenticator(kt keytab.Keytab) (a SPNEGOAuthenticator) {
	a.Config = NewConfig(kt)
	return
}

func NewConfig(kt keytab.Keytab) *Config {
	return &Config{Keytab: kt}
}

func (c *Config) Authenticate(neg, addr string) (i goidentity.Identity, ok bool, err error) {
	a := SPNEGOAuthenticator{
		SPNEGOHeaderValue: neg,
		ClientAddr:        addr,
		Config:            c,
	}
	b, err := base64.StdEncoding.DecodeString(a.SPNEGOHeaderValue)
	if err != nil {
		err = fmt.Errorf("SPNEGO error in base64 decoding negotiation header: %v", err)
		return
	}
	var spnego gssapi.SPNEGO
	err = spnego.Unmarshal(b)
	if !spnego.Init {
		err = fmt.Errorf("SPNEGO negotiation token is not a NegTokenInit: %v", err)
		return
	}
	if !spnego.NegTokenInit.MechTypes[0].Equal(gssapi.MechTypeOIDKRB5) {
		err = errors.New("SPNEGO OID of MechToken is not of type KRB5")
		return
	}
	var mt gssapi.MechToken
	err = mt.Unmarshal(spnego.NegTokenInit.MechToken)
	if err != nil {
		err = fmt.Errorf("SPNEGO error unmarshaling MechToken: %v", err)
		return
	}
	if !mt.IsAPReq() {
		err = errors.New("MechToken does not contain an AP_REQ - KRB_AP_ERR_MSG_TYPE")
		return
	}

	ok, creds, err := ValidateAPREQ(mt.APReq, a)
	if err != nil {
		err = fmt.Errorf("SPNEGO validation error: %v", err)
		return
	}
	i = &creds
	return
}

// Authenticate and retrieve a goidentity.Identity. In this case it is a pointer to a credentials.Credentials
func (a SPNEGOAuthenticator) Authenticate() (i goidentity.Identity, ok bool, err error) {
	return a.Config.Authenticate(a.SPNEGOHeaderValue, a.ClientAddr)
}

// Mechanism returns the authentication mechanism.
func (a SPNEGOAuthenticator) Mechanism() string {
	return "SPNEGO Kerberos"
}

// KRB5BasicAuthenticator implements gopkg.in/jcmturner/goidentity.v3.Authenticator interface.
// It takes username and password so can be used for basic authentication.
type KRB5BasicAuthenticator struct {
	SPN              string
	BasicHeaderValue string
	ServiceConfig    Config
	ClientConfig     *config.Config
	realm            string
	username         string
	password         string
}

// Authenticate and return the identity. The boolean indicates if the authentication was successful.
func (a KRB5BasicAuthenticator) Authenticate() (i goidentity.Identity, ok bool, err error) {
	a.realm, a.username, a.password, err = parseBasicHeaderValue(a.BasicHeaderValue)
	if err != nil {
		err = fmt.Errorf("could not parse basic authentication header: %v", err)
		return
	}
	cl := client.NewClientWithPassword(a.username, a.realm, a.password)
	cl.WithConfig(a.ClientConfig)
	err = cl.Login()
	if err != nil {
		// Username and/or password could be wrong
		err = fmt.Errorf("error with user credentials during login: %v", err)
		return
	}
	tkt, _, err := cl.GetServiceTicket(a.SPN)
	if err != nil {
		err = fmt.Errorf("could not get service ticket: %v", err)
		return
	}
	err = tkt.DecryptEncPart(a.ServiceConfig.Keytab, a.ServiceConfig.ServicePrincipal)
	if err != nil {
		err = fmt.Errorf("could not decrypt service ticket: %v", err)
		return
	}
	cl.Credentials.SetAuthTime(time.Now().UTC())
	cl.Credentials.SetAuthenticated(true)
	isPAC, pac, err := tkt.GetPACType(a.ServiceConfig.Keytab, a.ServiceConfig.ServicePrincipal)
	if isPAC && err != nil {
		err = fmt.Errorf("error processing PAC: %v", err)
		return
	}
	if isPAC {
		// There is a valid PAC. Adding attributes to creds
		cl.Credentials.SetADCredentials(credentials.ADCredentials{
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
	ok = true
	i = cl.Credentials
	return
}

// Mechanism returns the authentication mechanism.
func (a KRB5BasicAuthenticator) Mechanism() string {
	return "Kerberos Basic"
}

func parseBasicHeaderValue(s string) (domain, username, password string, err error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return
	}
	v := string(b)
	vc := strings.SplitN(v, ":", 2)
	password = vc[1]
	// Domain and username can be specified in 2 formats:
	// <Username> - no domain specified
	// <Domain>\<Username>
	// <Username>@<Domain>
	if strings.Contains(vc[0], `\`) {
		u := strings.SplitN(vc[0], `\`, 2)
		domain = u[0]
		username = u[1]
	} else if strings.Contains(vc[0], `@`) {
		u := strings.SplitN(vc[0], `@`, 2)
		domain = u[1]
		username = u[0]
	} else {
		username = vc[0]
	}
	return
}
