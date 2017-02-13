package main

import (
	"encoding/hex"
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/client"
	"github.com/jcmturner/gokrb5/config"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/types"
	"os"
)

const ktab = "05020000003b0001000b544553542e474f4b524235000974657374757365723100000001589b9b2b0100110010698c4df8e9f60e7eea5a21bf4526ad25000000010000004b0001000b544553542e474f4b524235000974657374757365723100000001589b9b2b0100120020bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de900000001"
const krb5conf = `[libdefaults]
  default_realm = TEST.GOKRB5
  dns_lookup_realm = false
  dns_lookup_kdc = false
  ticket_lifetime = 24h
  forwardable = yes
  default_tkt_enctypes = aes256-cts-hmac-sha1-96

[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88
  admin_server = 10.80.88.88:749
  default_domain = test.gokrb5
 }

[domain_realm]
 .test.gokrb5 = TEST.GOKRB5
 test.gokrb5 = TEST.GOKRB5`

func main() {

	c, err := config.NewConfigFromString(krb5conf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating config: %v", err)
	}
	fmt.Fprintf(os.Stdout, "Config: %+v\n", *c)
	a := messages.NewASReq(c, "testuser1")
	fmt.Fprintf(os.Stdout, "AS_REQ: %+v\n", a)
	b, err := a.Marshal()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling AS_REQ: %v\n", err)
	}
	rb, err := client.SendToKDC(c, b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error sending to KDC: %v\n", err)
	}
	var ar messages.ASRep
	ar.Unmarshal(rb)
	kb, _ := hex.DecodeString(ktab)
	kt, err := keytab.Parse(kb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "KT load err: %v\n\n", err)
	}
	err = ar.DecryptEncPartWithKeytab(kt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nDecrypt err: %v\n", err)
	} else {
		fmt.Fprintf(os.Stdout, "\n\nAS REP decrypted with keytab: %+v\n", ar)
		var p types.PAReqEncPARep
		_, err = asn1.Unmarshal(ar.DecryptedEncPart.EncPAData[0].PADataValue, &p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error unmarshal PAReqEncPARep: %v\n", err)
		}
		fmt.Fprintf(os.Stdout, "PAReqEncPARep: %+v\n", p)
		var et crypto.Aes256CtsHmacSha96
		cb, err := crypto.GetChecksum(b, ar.DecryptedEncPart.Key.KeyValue, messages.USAGE_KEY_USAGE_AS_REQ, et)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting checksum PAReqEncPARep: %v\n", err)
		} else {
			fmt.Fprintf(os.Stdout, "AS REQ checksum: %+v\n", cb[:et.GetHMACBitLength()/8])
		}
	}

}
