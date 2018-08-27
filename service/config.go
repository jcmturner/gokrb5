package service

import "gopkg.in/jcmturner/gokrb5.v5/keytab"

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
	KeytabPrincipal    string
	RequireHostAddr    bool
	DisablePACDecoding bool
}
