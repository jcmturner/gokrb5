# gokrb5

This is work in progress and does not yet work...

[![GoDoc](https://godoc.org/github.com/jcmturner/gokrb5?status.svg)](https://godoc.org/github.com/jcmturner/gokrb5)


## References
### RFCs
* RFC 4120 The Kerberos Network Authentication Service (V5)
[text](https://www.ietf.org/rfc/rfc4120.txt) [html](https://tools.ietf.org/html/rfc4120)
* RFC 3961 Encryption and Checksum Specifications for Kerberos 5
[text](https://www.ietf.org/rfc/rfc3961.txt) [html](https://tools.ietf.org/html/rfc3961)
* RFC 3962 Advanced Encryption Standard (AES) Encryption for Kerberos 5
[text](https://www.ietf.org/rfc/rfc3962.txt) [html](https://tools.ietf.org/html/rfc3962)
* [Microsoft PAC Validation](https://blogs.msdn.microsoft.com/openspecification/2009/04/24/understanding-microsoft-kerberos-pac-validation/)
* [Microsoft Kerberos Protocol Extensions](https://msdn.microsoft.com/en-us/library/cc233855.aspx)

### Useful Links
* https://en.wikipedia.org/wiki/Ciphertext_stealing#CBC_ciphertext_stealing

## Thanks
* Greg Hudson from the MIT Consortium for Kerberos and Internet Trust for providing useful test vectors.

## Known Issues
| Issue | Worked around? | References |
|-------|-------------|------------|
| Cannot unmarshal into slice of asn1.RawValue | Yes | https://github.com/golang/go/issues/17321 |
| Cannot marshal into a GeneralString | Yes - using https://github.com/jcmturner/asn1 | https://github.com/golang/go/issues/18832 |
| Cannot marshal into slice of strings and pass stringtype parameter tags to members | Yes - using https://github.com/jcmturner/asn1 | https://github.com/golang/go/issues/18834 |
| Cannot marshal with application tags | Yes | |