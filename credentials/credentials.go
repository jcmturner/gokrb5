package credentials

import "github.com/jcmturner/gokrb5/keytab"

type Credentials struct {
	Username string
	Keytab   keytab.Keytab
	Password string
}

func NewCredentials(username string) Credentials {
	return Credentials{
		Username: username,
		Keytab:   keytab.NewKeytab(),
	}
}

func (c *Credentials) WithKeytab(kt keytab.Keytab) *Credentials {
	c.Keytab = kt
	return c
}

func (c *Credentials) WithPassword(password string) *Credentials {
	c.Password = password
	return c
}

func (c *Credentials) HasKeytab() bool {
	if len(c.Keytab.Entries) > 0 {
		return true
	}
	return false
}

func (c *Credentials) HasPassword() bool {
	if c.Password != "" {
		return true
	}
	return false
}
