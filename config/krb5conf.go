package config

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/iana/etype"
	"io"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Implements KRB5 client and service configuration as described at https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html

// Struct representing the KRB5 configuration
type Config struct {
	LibDefaults *LibDefaults
	Realms      []Realm
	DomainRealm DomainRealm
	//CaPaths
	//AppDefaults
	//Plugins
}

// List of encryption types that have been deemed weak.
const (
	WEAK_ETYPE_LIST = "des-cbc-crc des-cbc-md4 des-cbc-md5 des-cbc-raw des3-cbc-raw des-hmac-sha1 arcfour-hmac-exp rc4-hmac-exp arcfour-hmac-md5-exp des"
)

// Create a new config struct
func NewConfig() *Config {
	d := make(DomainRealm)
	return &Config{
		LibDefaults: newLibDefaults(),
		DomainRealm: d,
	}
}

// Struct representing the [libdefaults] section of the configuration
type LibDefaults struct {
	Allow_weak_crypto bool //default false
	// ap_req_checksum_type int //unlikely to support this
	Canonicalize bool          //default false
	Ccache_type  int           //default is 4. unlikely to implement older
	Clockskew    time.Duration //max allowed skew in seconds, default 300
	//Default_ccache_name string // default /tmp/krb5cc_%{uid} //Not implementing as will hold in memory
	Default_client_keytab_name string //default /usr/local/var/krb5/user/%{euid}/client.keytab
	Default_keytab_name        string //default /etc/krb5.keytab
	Default_realm              string
	Default_tgs_enctypes       []string //default aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac camellia128-cts-cmac des-cbc-crc des-cbc-md5 des-cbc-md4
	Default_tkt_enctypes       []string //default aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac camellia128-cts-cmac des-cbc-crc des-cbc-md5 des-cbc-md4
	Default_tgs_enctype_ids    []int    //default aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac camellia128-cts-cmac des-cbc-crc des-cbc-md5 des-cbc-md4
	Default_tkt_enctype_ids    []int    //default aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac camellia128-cts-cmac des-cbc-crc des-cbc-md5 des-cbc-md4
	Dns_canonicalize_hostname  bool     //default true
	Dns_lookup_kdc             bool     //default false
	Dns_lookup_realm           bool
	//extra_addresses []net.IPAddr //Not implementing yet
	Forwardable              bool           //default false
	Ignore_acceptor_hostname bool           //default false
	K5login_authoritative    bool           //default false
	K5login_directory        string         //default user's home directory. Must be owned by the user or root
	Kdc_default_options      asn1.BitString //default 0x00000010 (KDC_OPT_RENEWABLE_OK)
	Kdc_timesync             int            //default 1
	//kdc_req_checksum_type int //unlikely to implement as for very old KDCs
	Noaddresses           bool     //default true
	Permitted_enctypes    []string //default aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac camellia128-cts-cmac des-cbc-crc des-cbc-md5 des-cbc-md4
	Permitted_enctype_ids []int
	//plugin_base_dir string //not supporting plugins
	Preferred_preauth_types []int         //default “17, 16, 15, 14”, which forces libkrb5 to attempt to use PKINIT if it is supported
	Proxiable               bool          //default false
	Rdns                    bool          //default true
	Realm_try_domains       int           //default -1
	Renew_lifetime          time.Duration //default 0
	Safe_checksum_type      int           //default 8
	Ticket_lifetime         time.Duration //default 1 day
	Udp_preference_limit    int           // 1 means to always use tcp. MIT krb5 has a default value of 1465, and it prevents user setting more than 32700.
	Verify_ap_req_nofail    bool          //default false
}

// Create a new LibDefaults struct
func newLibDefaults() *LibDefaults {
	usr, _ := user.Current()
	opts := asn1.BitString{}
	opts.Bytes, _ = hex.DecodeString("00000010")
	opts.BitLength = len(opts.Bytes) * 8
	return &LibDefaults{
		Ccache_type:                4,
		Clockskew:                  time.Duration(300) * time.Second,
		Default_client_keytab_name: fmt.Sprintf("/usr/local/var/krb5/user/%v/client.keytab", usr.Uid),
		Default_keytab_name:        "/etc/krb5.keytab",
		Default_tgs_enctypes:       []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "des3-cbc-sha1", "arcfour-hmac-md5", "camellia256-cts-cmac", "camellia128-cts-cmac", "des-cbc-crc", "des-cbc-md5", "des-cbc-md4"},
		Default_tkt_enctypes:       []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "des3-cbc-sha1", "arcfour-hmac-md5", "camellia256-cts-cmac", "camellia128-cts-cmac", "des-cbc-crc", "des-cbc-md5", "des-cbc-md4"},
		Dns_canonicalize_hostname:  true,
		K5login_directory:          usr.HomeDir,
		Kdc_default_options:        opts,
		Kdc_timesync:               1,
		Noaddresses:                true,
		Permitted_enctypes:         []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "des3-cbc-sha1", "arcfour-hmac-md5", "camellia256-cts-cmac", "camellia128-cts-cmac", "des-cbc-crc", "des-cbc-md5", "des-cbc-md4"},
		Preferred_preauth_types:    []int{17, 16, 15, 14},
		Rdns:                 true,
		Realm_try_domains:    -1,
		Safe_checksum_type:   8,
		Ticket_lifetime:      time.Duration(24) * time.Hour,
		Udp_preference_limit: 1465,
	}
}

// Parse the lines of the [libdefaults] section of the configuration into the LibDefaults struct
func (l *LibDefaults) parseLines(lines []string) error {
	for _, line := range lines {
		if !strings.Contains(line, "=") {
			return fmt.Errorf("libdefaults configuration line invalid: %s", line)
		}

		p := strings.Split(line, "=")
		key := strings.Replace(strings.ToLower(p[0]), " ", "", -1)
		switch key {
		case "allow_weak_crypto":
			v, err := parseBoolean(p[1])
			if err != nil {
				return fmt.Errorf("libdefaults configuration line invalid. %v: %s", err, line)
			}
			l.Allow_weak_crypto = v
		case "canonicalize":
			v, err := parseBoolean(p[1])
			if err != nil {
				return fmt.Errorf("libdefaults configuration line invalid. %v: %s", err, line)
			}
			l.Canonicalize = v
		case "ccache_type":
			p[1] = strings.Replace(p[1], " ", "", -1)
			v, err := strconv.ParseUint(p[1], 10, 32)
			if err != nil || v < 0 || v > 4 {
				return fmt.Errorf("libdefaults configuration line invalid: %s", line)
			}
			l.Ccache_type = int(v)
		case "clockskew":
			d, err := parseDuration(p[1])
			if err != nil {
				return fmt.Errorf("libdefaults configuration line invalid. %v: %s", err, line)
			}
			l.Clockskew = d
		case "default_client_keytab_name":
			l.Default_client_keytab_name = strings.Replace(p[1], " ", "", -1)
		case "default_keytab_name":
			l.Default_keytab_name = strings.Replace(p[1], " ", "", -1)
		case "default_realm":
			l.Default_realm = strings.Replace(p[1], " ", "", -1)
		case "default_tgs_enctypes":
			l.Default_tgs_enctypes = strings.Fields(p[1])
		case "default_tkt_enctypes":
			l.Default_tkt_enctypes = strings.Fields(p[1])
		case "dns_canonicalize_hostname":
			v, err := parseBoolean(p[1])
			if err != nil {
				return fmt.Errorf("libdefaults configuration line invalid. %v: %s", err, line)
			}
			l.Dns_canonicalize_hostname = v
		case "dns_lookup_kdc":
			v, err := parseBoolean(p[1])
			if err != nil {
				return fmt.Errorf("libdefaults configuration line invalid. %v: %s", err, line)
			}
			l.Dns_lookup_kdc = v
		case "dns_lookup_realm":
			v, err := parseBoolean(p[1])
			if err != nil {
				return fmt.Errorf("libdefaults configuration line invalid. %v: %s", err, line)
			}
			l.Dns_lookup_realm = v
		case "forwardable":
			v, err := parseBoolean(p[1])
			if err != nil {
				return fmt.Errorf("libdefaults configuration line invalid. %v: %s", err, line)
			}
			l.Forwardable = v
		case "ignore_acceptor_hostname":
			v, err := parseBoolean(p[1])
			if err != nil {
				return fmt.Errorf("libdefaults configuration line invalid. %v: %s", err, line)
			}
			l.Ignore_acceptor_hostname = v
		case "k5login_authoritative":
			v, err := parseBoolean(p[1])
			if err != nil {
				return fmt.Errorf("libdefaults configuration line invalid. %v: %s", err, line)
			}
			l.K5login_authoritative = v
		case "k5login_directory":
			l.K5login_directory = strings.Replace(p[1], " ", "", -1)
		case "kdc_default_options":
			v := strings.Replace(p[1], " ", "", -1)
			v = strings.Replace(v, "0x", "", -1)
			b, err := hex.DecodeString(v)
			if err != nil {
				return fmt.Errorf("libdefaults configuration line invalid: %s", line)
			}
			l.Kdc_default_options.Bytes = b
			l.Kdc_default_options.BitLength = len(b) * 8
		case "kdc_timesync":
			p[1] = strings.Replace(p[1], " ", "", -1)
			v, err := strconv.ParseInt(p[1], 10, 32)
			if err != nil || v < 0 {
				return fmt.Errorf("libdefaults configuration line invalid: %s", line)
			}
			l.Kdc_timesync = int(v)
		case "noaddresses":
			v, err := parseBoolean(p[1])
			if err != nil {
				return fmt.Errorf("libdefaults configuration line invalid. %v: %s", err, line)
			}
			l.Noaddresses = v
		case "permitted_enctypes":
			l.Permitted_enctypes = strings.Fields(p[1])
		case "preferred_preauth_types":
			p[1] = strings.Replace(p[1], " ", "", -1)
			t := strings.Split(p[1], ",")
			var v []int
			for _, s := range t {
				i, err := strconv.ParseInt(s, 10, 32)
				if err != nil {
					return fmt.Errorf("libdefaults configuration line invalid: %s", line)
				}
				v = append(v, int(i))
			}
			l.Preferred_preauth_types = v
		case "proxiable":
			v, err := parseBoolean(p[1])
			if err != nil {
				return fmt.Errorf("libdefaults configuration line invalid. %v: %s", err, line)
			}
			l.Proxiable = v
		case "rdns":
			v, err := parseBoolean(p[1])
			if err != nil {
				return fmt.Errorf("libdefaults configuration line invalid. %v: %s", err, line)
			}
			l.Rdns = v
		case "realm_try_domains":
			p[1] = strings.Replace(p[1], " ", "", -1)
			v, err := strconv.ParseInt(p[1], 10, 32)
			if err != nil || v < -1 {
				return fmt.Errorf("libdefaults configuration line invalid: %s", line)
			}
			l.Realm_try_domains = int(v)
		case "renew_lifetime":
			d, err := parseDuration(p[1])
			if err != nil {
				return fmt.Errorf("libdefaults configuration line invalid. %v: %s", err, line)
			}
			l.Renew_lifetime = d
		case "safe_checksum_type":
			p[1] = strings.Replace(p[1], " ", "", -1)
			v, err := strconv.ParseInt(p[1], 10, 32)
			if err != nil || v < 0 {
				return fmt.Errorf("libdefaults configuration line invalid: %s", line)
			}
			l.Safe_checksum_type = int(v)
		case "ticket_lifetime":
			d, err := parseDuration(p[1])
			if err != nil {
				return fmt.Errorf("libdefaults configuration line invalid. %v: %s", err, line)
			}
			l.Ticket_lifetime = d
		case "udp_preference_limit":
			p[1] = strings.Replace(p[1], " ", "", -1)
			v, err := strconv.ParseUint(p[1], 10, 32)
			if err != nil || v > 32700 {
				return fmt.Errorf("libdefaults configuration line invalid: %s", line)
			}
			l.Udp_preference_limit = int(v)
		case "verify_ap_req_nofail":
			v, err := parseBoolean(p[1])
			if err != nil {
				return fmt.Errorf("libdefaults configuration line invalid. %v: %s", err, line)
			}
			l.Verify_ap_req_nofail = v
		default:
			//Ignore the line
			continue
		}
	}
	l.Default_tgs_enctype_ids = parseETypes(l.Default_tgs_enctypes, l.Allow_weak_crypto)
	l.Default_tkt_enctype_ids = parseETypes(l.Default_tkt_enctypes, l.Allow_weak_crypto)
	l.Permitted_enctype_ids = parseETypes(l.Permitted_enctypes, l.Allow_weak_crypto)
	return nil
}

// Struct representing an entry in the [realms] section of the configuration
type Realm struct {
	Realm        string
	Admin_server []string
	//auth_to_local //Not implementing for now
	//auth_to_local_names //Not implementing for now
	Default_domain string
	Kdc            []string
	Kpasswd_server []string //default admin_server:464
	Master_kdc     []string
}

// Parse the lines of a [realms] entry into the Realm struct
func (r *Realm) parseLines(name string, lines []string) error {
	r.Realm = name
	var admin_server_final bool
	var kdc_final bool
	var kpasswd_server_final bool
	var master_kdc_final bool
	for _, line := range lines {
		if !strings.Contains(line, "=") {
			return fmt.Errorf("Realm configuration line invalid: %s", line)
		}

		p := strings.Split(line, "=")
		key := strings.Replace(strings.ToLower(p[0]), " ", "", -1)
		v := strings.Replace(p[1], " ", "", -1)
		switch key {
		case "admin_server":
			appendUntilFinal(&r.Admin_server, v, &admin_server_final)
		case "default_domain":
			r.Default_domain = v
		case "kdc":
			appendUntilFinal(&r.Kdc, v, &kdc_final)
		case "kpasswd_server":
			appendUntilFinal(&r.Kpasswd_server, v, &kpasswd_server_final)
		case "master_kdc":
			appendUntilFinal(&r.Master_kdc, v, &master_kdc_final)
		default:
			//Ignore the line
			continue
		}
	}
	//default for Kpasswd_server = admin_server:464
	if len(r.Kpasswd_server) < 1 {
		for _, a := range r.Admin_server {
			s := strings.Split(a, ":")
			r.Kpasswd_server = append(r.Kpasswd_server, s[0]+":464")
		}
	}
	return nil
}

// Parse the lines of the [realms] section of the configuration into an slice of Realm structs
func parseRealms(lines []string) ([]Realm, error) {
	var realms []Realm
	start := -1
	var name string
	for i, l := range lines {
		if strings.Contains(l, "{") {
			if start >= 0 {
				// already started a block!!!
				return nil, errors.New("Invalid Realms section in configuration.")
			}
			start = i
			if !strings.Contains(l, "=") {
				return nil, fmt.Errorf("Realm configuration line invalid: %s", l)
			}
			p := strings.Split(l, "=")
			name = strings.Replace(p[0], " ", "", -1)
		}
		if strings.Contains(l, "}") {
			if start < 0 {
				// but not started a block!!!
				return nil, errors.New("Invalid Realms section in configuration.")
			}
			var r Realm
			r.parseLines(name, lines[start+1:i])
			realms = append(realms, r)
			start = -1
		}
	}
	return realms, nil
}

// Mapping of domains to realms representing the [domain_realm] section of the configuration
type DomainRealm map[string]string

// Parse the lines of the [domain_realm] section of the configuration and add to the mapping
func (d *DomainRealm) parseLines(lines []string) error {
	for _, line := range lines {
		if !strings.Contains(line, "=") {
			return fmt.Errorf("Realm configuration line invalid: %s", line)
		}
		p := strings.Split(line, "=")
		domain := strings.Replace(strings.ToLower(p[0]), " ", "", -1)
		realm := strings.Replace(strings.ToUpper(p[1]), " ", "", -1)
		d.addMapping(domain, realm)
	}
	return nil
}

// Add a domain to realm mapping
func (d *DomainRealm) addMapping(domain, realm string) {
	(*d)[domain] = realm
}

// Delete a domain to realm mapping
func (d *DomainRealm) deleteMapping(domain, realm string) {
	delete(*d, domain)
}

// Resolve the realm for the specified domain name from the domain to realm mapping.
// The most specific mapping is returned.
func (c *Config) ResolveRealm(domainName string) string {
	domainName = strings.TrimSuffix(domainName, ".")
	periods := strings.Count(domainName, ".") + 1
	for i := 1; i <= periods; i +=1 {
		z := strings.SplitN(domainName, ".", i)
		if r, ok := c.DomainRealm[z[len(z)-1]]; ok {
			return r
		}
	}
	return c.LibDefaults.Default_realm
}

// Load the KRB5 configuration from the specified file path
func Load(cfgPath string) (*Config, error) {
	fh, err := os.Open(cfgPath)
	if err != nil {
		return nil, errors.New("Configuration file could not be openned: " + cfgPath + " " + err.Error())
	}
	defer fh.Close()
	scanner := bufio.NewScanner(fh)
	return NewConfigFromScanner(scanner)
}

// Create a new Config struct from a string
func NewConfigFromString(s string) (*Config, error) {
	reader := strings.NewReader(s)
	return NewConfigFromReader(reader)
}

// Create a new Config struct from an io.Reader
func NewConfigFromReader(r io.Reader) (*Config, error) {
	scanner := bufio.NewScanner(r)
	return NewConfigFromScanner(scanner)
}

// Create a new Config struct from a bufio.Scanner
func NewConfigFromScanner(scanner *bufio.Scanner) (*Config, error) {
	c := NewConfig()
	sections := make(map[int]string)
	var section_line_num []int
	var lines []string
	for scanner.Scan() {
		// Skip comments and blank lines
		if matched, _ := regexp.MatchString(`\s*(#|;|\n)`, scanner.Text()); matched {
			continue
		}
		if matched, _ := regexp.MatchString(`\s*\[libdefaults\]\s*`, scanner.Text()); matched {
			sections[len(lines)] = "libdefaults"
			section_line_num = append(section_line_num, len(lines))
			continue
		}
		if matched, _ := regexp.MatchString(`\s*\[realms\]\s*`, scanner.Text()); matched {
			sections[len(lines)] = "realms"
			section_line_num = append(section_line_num, len(lines))
			continue
		}
		if matched, _ := regexp.MatchString(`\s*\[domain_realm\]\s*`, scanner.Text()); matched {
			sections[len(lines)] = "domain_realm"
			section_line_num = append(section_line_num, len(lines))
			continue
		}
		if matched, _ := regexp.MatchString(`\s*\[.*\]\s*`, scanner.Text()); matched {
			sections[len(lines)] = "unknown_section"
			section_line_num = append(section_line_num, len(lines))
			continue
		}
		lines = append(lines, scanner.Text())
	}
	for i, start := range section_line_num {
		var end int
		if i+1 >= len(section_line_num) {
			end = len(lines) - 1
		} else {
			end = section_line_num[i+1] - 1
		}
		switch section := sections[start]; section {
		case "libdefaults":
			err := c.LibDefaults.parseLines(lines[start:end])
			if err != nil {
				return nil, fmt.Errorf("Error processing libdefaults section: %v", err)
			}
		case "realms":
			realms, err := parseRealms(lines[start:end])
			if err != nil {
				return nil, fmt.Errorf("Error processing realms section: %v", err)
			}
			c.Realms = realms
		case "domain_realm":
			err := c.DomainRealm.parseLines(lines[start:end])
			if err != nil {
				return nil, fmt.Errorf("Error processing domaain_realm section: %v", err)
			}
		default:
			continue
		}
	}
	return c, nil
}

// Parse a space delimited list of ETypes into a list of EType numbers optionally filtering out weak ETypes
func parseETypes(s []string, w bool) []int {
	var eti []int
	for _, et := range s {
		if !w {
			var weak bool
			for _, wet := range strings.Fields(WEAK_ETYPE_LIST) {
				if et == wet {
					weak = true
					break
				}
			}
			if weak {
				continue
			}
		}
		i := etype.ETypesByName[et]
		if i != 0 {
			eti = append(eti, i)
		}
	}
	return eti
}

// Parse a time duration string in the configuration to a golang time.Duration.
func parseDuration(s string) (time.Duration, error) {
	s = strings.Replace(s, " ", "", -1)
	d, err := time.ParseDuration(s)
	if err == nil {
		return d, nil
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err == nil && v > 0 {
		return time.Duration(v) * time.Second, nil
	}
	if strings.Contains(s, ":") {
		t := strings.Split(s, ":")
		if 2 > len(t) || len(t) > 3 {
			return time.Duration(0), errors.New("Invalid time duration value")
		}
		var i []int
		for _, n := range t {
			j, err := strconv.ParseInt(n, 10, 16)
			if err != nil {
				return time.Duration(0), errors.New("Invalid time duration value")
			}
			i = append(i, int(j))
		}
		d := time.Duration(i[0])*time.Hour + time.Duration(i[1])*time.Minute
		if len(i) == 3 {
			d = d + time.Duration(i[2])*time.Second
		}
		return d, nil
	}
	return time.Duration(0), errors.New("Invalid time duration value")
}

// Parse possible boolean values to golang bool
func parseBoolean(s string) (bool, error) {
	s = strings.Replace(s, " ", "", -1)
	v, err := strconv.ParseBool(s)
	if err == nil {
		return v, nil
	}
	switch strings.ToLower(s) {
	case "yes":
		return true, nil
	case "y":
		return true, nil
	case "no":
		return false, nil
	case "n":
		return false, nil
	}
	return false, errors.New("Invalid boolean value")
}

// Parse array of strings but stop if an asterisk is placed at the end of a line
func appendUntilFinal(s *[]string, value string, final *bool) {
	if *final {
		return
	}
	if last := len(value) - 1; last >= 0 && value[last] == '*' {
		*final = true
		value = value[:len(value)-1]
	}
	*s = append(*s, value)
}
