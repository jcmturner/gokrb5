// Package credentials provides credentials management for Kerberos 5 authentication.
package credentials

import (
	"github.com/jcmturner/gokrb5/iana/nametype"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/types"
	"time"
)

// Credentials struct for a user.
// Contains either a keytab, password or both.
// Keytabs are used over passwords if both are defined.
type Credentials struct {
	Username   string
	Realm      string
	CName      types.PrincipalName
	Keytab     keytab.Keytab
	Password   string
	Attributes map[string]interface{}
}

// ADCredentials contains information obtained from the PAC.
type ADCredentials struct {
	EffectiveName       string
	FullName            string
	UserID              int
	PrimaryGroupID      int
	LogOnTime           time.Time
	LogOffTime          time.Time
	PasswordLastSet     time.Time
	GroupMembershipSIDs []string
	LogonDomainName     string
	LogonDomainID       string
	LogonServer         string
}

// NewCredentials creates a new Credentials instance.
func NewCredentials(username string, realm string) Credentials {
	return Credentials{
		Username: username,
		Realm:    realm,
		CName: types.PrincipalName{
			NameType:   nametype.KRB_NT_PRINCIPAL,
			NameString: []string{username},
		},
		Keytab:     keytab.NewKeytab(),
		Attributes: make(map[string]interface{}),
	}
}

// NewCredentialsFromPrincipal creates a new Credentials instance with the user details provides as a PrincipalName type.
func NewCredentialsFromPrincipal(cname types.PrincipalName, realm string) Credentials {
	return Credentials{
		Username:   cname.GetPrincipalNameString(),
		Realm:      realm,
		CName:      cname,
		Keytab:     keytab.NewKeytab(),
		Attributes: make(map[string]interface{}),
	}
}

// WithKeytab sets the Keytab in the Credentials struct.
func (c *Credentials) WithKeytab(kt keytab.Keytab) *Credentials {
	c.Keytab = kt
	return c
}

// WithPassword sets the password in the Credentials struct.
func (c *Credentials) WithPassword(password string) *Credentials {
	c.Password = password
	return c
}

// HasKeytab queries if the Credentials has a keytab defined.
func (c *Credentials) HasKeytab() bool {
	if len(c.Keytab.Entries) > 0 {
		return true
	}
	return false
}

// HasPassword queries if the Credentials has a password defined.
func (c *Credentials) HasPassword() bool {
	if c.Password != "" {
		return true
	}
	return false
}
