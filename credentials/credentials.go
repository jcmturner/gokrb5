package credentials

import "github.com/jcmturner/gokrb5/keytab"

// Credentials struct for a user.
// Contains either a keytab, password or both.
// Keytabs are used over passwords if both are defined.
type Credentials struct {
	Username string
	Keytab   keytab.Keytab
	Password string
}

// Create a new Credentials struct.
func NewCredentials(username string) Credentials {
	return Credentials{
		Username: username,
		Keytab:   keytab.NewKeytab(),
	}
}

// Set the Keytab in the Credentials struct.
func (c *Credentials) WithKeytab(kt keytab.Keytab) *Credentials {
	c.Keytab = kt
	return c
}

// Set the password in the Credentials struct.
func (c *Credentials) WithPassword(password string) *Credentials {
	c.Password = password
	return c
}

// Query if the Credentials has a keytab defined.
func (c *Credentials) HasKeytab() bool {
	if len(c.Keytab.Entries) > 0 {
		return true
	}
	return false
}

// Query if the Credentials has a password defined.
func (c *Credentials) HasPassword() bool {
	if c.Password != "" {
		return true
	}
	return false
}
