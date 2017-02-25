package client

import (
	"github.com/jcmturner/gokrb5/config"
	"github.com/jcmturner/gokrb5/credentials"
	"github.com/jcmturner/gokrb5/keytab"
)

type Client struct {
	Credentials *credentials.Credentials
	Config      *config.Config
	Session     *Session
}

func NewClientWithPassword(username, password string) Client {
	creds := credentials.NewCredentials(username)
	return Client{
		Credentials: creds.WithPassword(password),
		Config:      config.NewConfig(),
	}
}

func NewClientWithKeytab(username string, kt keytab.Keytab) Client {
	creds := credentials.NewCredentials(username)
	return Client{
		Credentials: creds.WithKeytab(kt),
		Config:      config.NewConfig(),
	}
}

func (cl *Client) WithConfig(cfg *config.Config) *Client {
	cl.Config = cfg
	return cl
}

func (cl *Client) LoadConfig(cfgPath string) (*Client, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return cl, err
	}
	cl.Config = cfg
	return cl, nil
}

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
