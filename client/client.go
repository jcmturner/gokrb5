// Package client provides a client library and methods for Kerberos 5 authentication.
package client

import (
	"fmt"
	"github.com/jcmturner/gokrb5/config"
	"github.com/jcmturner/gokrb5/credentials"
	"github.com/jcmturner/gokrb5/iana/nametype"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/types"
)

// Client side configuration and state.
type Client struct {
	Credentials *credentials.Credentials
	Config      *config.Config
	GoKrb5Conf  *Config
	session     *session
	Cache       *Cache
}

// Config struct holds GoKRB5 specific client configurations.
// Set Disable_PA_FX_FAST to true to force this behaviour off.
// Set Assume_PA_ENC_TIMESTAMP_Required to send the PA_ENC_TIMESTAMP pro-actively rather than waiting for a KRB_ERROR response from the KDC indicating it is required.
type Config struct {
	Disable_PA_FX_FAST               bool
	Assume_PA_ENC_TIMESTAMP_Required bool
}

// NewClientWithPassword creates a new client from a password credential.
func NewClientWithPassword(username, realm, password string) Client {
	creds := credentials.NewCredentials(username, realm)
	return Client{
		Credentials: creds.WithPassword(password),
		Config:      config.NewConfig(),
		GoKrb5Conf:  &Config{},
		session:     &session{},
		Cache:       NewCache(),
	}
}

// NewClientWithKeytab creates a new client from a keytab credential.
func NewClientWithKeytab(username, realm string, kt keytab.Keytab) Client {
	creds := credentials.NewCredentials(username, realm)
	return Client{
		Credentials: creds.WithKeytab(kt),
		Config:      config.NewConfig(),
		GoKrb5Conf:  &Config{},
		session:     &session{},
		Cache:       NewCache(),
	}
}

// NewClientFromCCache create a client from a populated client cache.
//
// WARNING: If you do not add a keytab or password to the client then the TGT cannot be renewed and a failure will occur after the TGT expires.
func NewClientFromCCache(c credentials.CCache) (Client, error) {
	cl := Client{
		Credentials: c.GetClientCredentials(),
		Config:      config.NewConfig(),
		GoKrb5Conf:  &Config{},
		Cache:       NewCache(),
	}
	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", c.DefaultPrincipal.Realm},
	}
	cred, err := c.GetEntry(spn)
	if err != nil {
		return cl, err
	}
	var tgt messages.Ticket
	err = tgt.Unmarshal(cred.Ticket)
	if err != nil {
		return cl, fmt.Errorf("TGT bytes in cache are not valid: %v", err)
	}
	cl.session = &session{
		AuthTime:   cred.AuthTime,
		EndTime:    cred.EndTime,
		RenewTill:  cred.RenewTill,
		TGT:        tgt,
		SessionKey: cred.Key,
	}
	for _, cred := range c.GetEntries() {
		var tkt messages.Ticket
		err = tkt.Unmarshal(cred.Ticket)
		if err != nil {
			return cl, fmt.Errorf("Cache entry ticket bytes are not valid: %v", err)
		}
		cl.Cache.addEntry(
			tkt,
			cred.AuthTime,
			cred.StartTime,
			cred.EndTime,
			cred.RenewTill,
			cred.Key,
		)
	}
	return cl, nil
}

// WithConfig sets the Kerberos configuration for the client.
func (cl *Client) WithConfig(cfg *config.Config) *Client {
	cl.Config = cfg
	return cl
}

// WithKeytab adds a keytab to the client
func (cl *Client) WithKeytab(kt keytab.Keytab) *Client {
	cl.Credentials.WithKeytab(kt)
	return cl
}

// WithPassword adds a password to the client
func (cl *Client) WithPassword(password string) *Client {
	cl.Credentials.WithPassword(password)
	return cl
}

// LoadConfig loads the Kerberos configuration for the client from file path specified.
func (cl *Client) LoadConfig(cfgPath string) (*Client, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return cl, err
	}
	cl.Config = cfg
	return cl, nil
}

// IsConfigured indicates if the client has the values required set.
func (cl *Client) IsConfigured() bool {
	if !cl.Credentials.HasPassword() && !cl.Credentials.HasKeytab() {
		return false
	}
	if cl.Credentials.Username == "" {
		return false
	}
	if cl.Config.LibDefaults.Default_realm == "" {
		return false
	}
	for _, r := range cl.Config.Realms {
		if r.Realm == cl.Config.LibDefaults.Default_realm {
			if len(r.Kdc) > 0 {
				return true
			}
			return false
		}
	}
	return false
}

// Login the client with the KDC via an AS exchange.
func (cl *Client) Login() error {
	return cl.ASExchange()
}
