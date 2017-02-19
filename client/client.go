package client

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/config"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/iana/keyusage"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/types"
	"math/rand"
	"net"
	"os"
	"time"
)

type Client struct {
	Username string
	Password string
	Keytab   keytab.Keytab
	Config   *config.Config
}

func NewClientWithPassword(username, password string) Client {
	return Client{
		Username: username,
		Password: password,
		Keytab: keytab.NewKeytab(),
		Config: config.NewConfig(),
	}
}

func NewClientWithKeytab(username string, kt keytab.Keytab) Client {
	return Client{
		Username: username,
		Keytab:   kt,
		Config: config.NewConfig(),
	}
}

func (cl *Client) WithPassword(p string) *Client {
	cl.Password = p
	return cl
}

func (cl *Client) WithKeytab(kt keytab.Keytab) *Client {
	cl.Keytab = kt
	return cl
}

func (cl *Client) WithConfig(cfg config.Config) *Client {
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
	if cl.Password == "" && len(cl.Keytab.Entries) < 1 {
		return false
	}
	if cl.Username == "" {
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



