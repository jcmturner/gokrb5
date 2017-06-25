// Package client provides a client library and methods for Kerberos 5 authentication.
package client

import (
	"github.com/jcmturner/gokrb5/config"
	"github.com/jcmturner/gokrb5/credentials"
	"github.com/jcmturner/gokrb5/keytab"
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

// WithConfig sets the Kerberos configuration for the client.
func (cl *Client) WithConfig(cfg *config.Config) *Client {
	cl.Config = cfg
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
