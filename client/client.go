// A client for Kerberos 5 authentication.
package client

import (
	"github.com/jcmturner/gokrb5/config"
	"github.com/jcmturner/gokrb5/credentials"
	"github.com/jcmturner/gokrb5/keytab"
)

// Client struct.
type Client struct {
	Credentials *credentials.Credentials
	Config      *config.Config
	Session     *Session
	Cache       *Cache
}

// Create a new client with a password credential.
func NewClientWithPassword(username, realm, password string) Client {
	creds := credentials.NewCredentials(username, realm)
	return Client{
		Credentials: creds.WithPassword(password),
		Config:      config.NewConfig(),
		Session:     &Session{},
		Cache:       NewCache(),
	}
}

// Create a new client with a keytab credential.
func NewClientWithKeytab(username, realm string, kt keytab.Keytab) Client {
	creds := credentials.NewCredentials(username, realm)
	return Client{
		Credentials: creds.WithKeytab(kt),
		Config:      config.NewConfig(),
		Session:     &Session{},
		Cache:       NewCache(),
	}
}

// Set the Kerberos configuration for the client.
func (cl *Client) WithConfig(cfg *config.Config) *Client {
	cl.Config = cfg
	return cl
}

// Load the Kerberos configuration for the client from file path specified.
func (cl *Client) LoadConfig(cfgPath string) (*Client, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return cl, err
	}
	cl.Config = cfg
	return cl, nil
}

// Has the client got sufficient values required.
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
			} else {
				return false
			}
		}
	}
	return false
}
