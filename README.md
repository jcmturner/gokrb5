# gokrb5

This is work in progress and does not yet fully work...

[![GoDoc](https://godoc.org/github.com/jcmturner/gokrb5?status.svg)](https://godoc.org/github.com/jcmturner/gokrb5)

## Implemented Encryption & Checksum Types
The currently implemented encrytion types are:

| Implementation | Encryption ID | Checksum ID |
|-------|-------------|------------|
| aes128-cts-hmac-sha1-96 | 17 | 15 |
| aes256-cts-hmac-sha1-96 | 18 | 16 |

## Usage
### Configuration
The gokrb5 libraries use the same krb5.conf configuration file format as MIT Kerberos, described [here](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html).
Config instances can be created by loading from a file path or by passing a string, io.Reader or bufio.Scanner to the relevant method:
```go
import "github.com/jcmturner/gokrb5/config"
cfg, err := config.Load("/path/to/config/file")
cfg, err := config.NewConfigFromString(krb5Str) //String must have appropriate newline separations
cfg, err := config.NewConfigFromReader(reader)
cfg, err := config.NewConfigFromScanner(scanner)
```
### Keytab files
Standard keytab files can be read from a file or from a slice of bytes:
```go
import 	"github.com/jcmturner/gokrb5/keytab"
ktFromFile, err := keytab.Load("/path/to/file.keytab")
ktFromBytes, err := keytab.Parse(b)

```
### Kerberos Client
Create a client instance with either a password or a keytab:
```go
import 	"github.com/jcmturner/gokrb5/client"
cl := client.NewClientWithPassword("username", "REALM.COM", "password")
cl := client.NewClientWithKeytab("username", "REALM.COM", kt)

```
Provide configuration to the client:
```go
cl.WithConfig(cfg)
```
Login:
```go
err := cl.Login
```
(Optional) Enable automatic refresh of Kerberos Ticket Granting Ticket (TGT):
```go
cl.EnableAutoSessionRenewal()
```
Request a Serivce ticket for a Service Principal Name (SPN).
This method will use the client's cache either returning a valid cached ticket, renewing a cached ticket with the KDC or requesting a new ticket from the KDC.
Therefore the GetServiceTicket method can be continually used for the most efficient interaction with the KDC.
```go
tkt, err := cl.GetServiceTicket("HTTP/host.test.gokrb5")
```

## References
### RFCs
* RFC 4120 The Kerberos Network Authentication Service (V5)
[text](https://www.ietf.org/rfc/rfc4120.txt) [html](https://tools.ietf.org/html/rfc4120)
* RFC 3961 Encryption and Checksum Specifications for Kerberos 5
[text](https://www.ietf.org/rfc/rfc3961.txt) [html](https://tools.ietf.org/html/rfc3961)
* RFC 3962 Advanced Encryption Standard (AES) Encryption for Kerberos 5
[text](https://www.ietf.org/rfc/rfc3962.txt) [html](https://tools.ietf.org/html/rfc3962)
* RFC 4178 The Simple and Protected Generic Security Service Application Program Interface (GSS-API) Negotiation Mechanism
[text](https://www.ietf.org/rfc/rfc4178.txt) [html](https://tools.ietf.org/html/rfc4178.html)
* RFC 4559 SPNEGO-based Kerberos and NTLM HTTP Authentication in Microsoft Windows
[text](https://www.ietf.org/rfc/rfc4559.txt) [html](https://tools.ietf.org/html/rfc4559.html)
* RFC 6806 Kerberos Principal Name Canonicalization and Cross-Realm Referrals
[text](https://www.ietf.org/rfc/rfc6806.txt) [html](https://tools.ietf.org/html/rfc6806.html)
* RFC 6113 A Generalized Framework for Kerberos Pre-Authentication
[text](https://www.ietf.org/rfc/rfc6113.txt) [html](https://tools.ietf.org/html/rfc6113.html)
* [IANA Assigned Kerberos Numbers](http://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml)
* [Microsoft PAC Validation](https://blogs.msdn.microsoft.com/openspecification/2009/04/24/understanding-microsoft-kerberos-pac-validation/)
* [Microsoft Kerberos Protocol Extensions](https://msdn.microsoft.com/en-us/library/cc233855.aspx)

### Useful Links
* https://en.wikipedia.org/wiki/Ciphertext_stealing#CBC_ciphertext_stealing

## Thanks
* Greg Hudson from the MIT Consortium for Kerberos and Internet Trust for providing useful advice.

## Known Issues
| Issue | Worked around? | References |
|-------|-------------|------------|
| Golang's ASN1 package cannot unmarshal into slice of asn1.RawValue | Yes | https://github.com/golang/go/issues/17321 |
| Golang's ASN1 package cannot marshal into a GeneralString | Yes - using https://github.com/jcmturner/asn1 | https://github.com/golang/go/issues/18832 |
| Golang's ASN1 package cannot marshal into slice of strings and pass stringtype parameter tags to members | Yes - using https://github.com/jcmturner/asn1 | https://github.com/golang/go/issues/18834 |
| Golang's ASN1 package cannot marshal with application tags | Yes | |