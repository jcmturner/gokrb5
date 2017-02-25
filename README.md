# gokrb5

This is work in progress and does not yet work...

[![GoDoc](https://godoc.org/github.com/jcmturner/gokrb5?status.svg)](https://godoc.org/github.com/jcmturner/gokrb5)

## Compatibility
Go version 1.8+ is needed.

## References
### RFCs
* RFC 4120 The Kerberos Network Authentication Service (V5)
[text](https://www.ietf.org/rfc/rfc4120.txt) [html](https://tools.ietf.org/html/rfc4120)
* RFC 3961 Encryption and Checksum Specifications for Kerberos 5
[text](https://www.ietf.org/rfc/rfc3961.txt) [html](https://tools.ietf.org/html/rfc3961)
* RFC 3962 Advanced Encryption Standard (AES) Encryption for Kerberos 5
[text](https://www.ietf.org/rfc/rfc3962.txt) [html](https://tools.ietf.org/html/rfc3962)
* RFC 6806 Kerberos Principal Name Canonicalization and Cross-Realm Referrals [text](https://www.ietf.org/rfc/rfc6806.txt) [html](https://tools.ietf.org/html/rfc6806.html)
* RFC 6113 A Generalized Framework for Kerberos Pre-Authentication [text](https://www.ietf.org/rfc/rfc6113.txt) [html](https://tools.ietf.org/html/rfc6113.html)
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