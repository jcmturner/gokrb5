package main

import (
	"encoding/hex"
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/client"
	"github.com/jcmturner/gokrb5/config"
	"github.com/jcmturner/gokrb5/credentials"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/iana/keyusage"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/types"
	"github.com/jcmturner/gokrb5/testdata"
	"os"
	"time"
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
 test.gokrb5 = TEST.GOKRB5
 `
const noparep = "6b8202bc308202b8a003020105a10302010ba22e302c302aa103020113a2230421301f301da003020112a1161b14544553542e474f4b524235746573747573657231a30d1b0b544553542e474f4b524235a4163014a003020101a10d300b1b09746573747573657231a582015a6182015630820152a003020105a10d1b0b544553542e474f4b524235a220301ea003020100a11730151b066b72627467741b0b544553542e474f4b524235a382011830820114a003020112a103020101a2820106048201021ced05c1ad2bfcd32c14306cd0c2ed3499e0dbdff120f64151b0fc8fe15a5f4dcc185cd14a9d67570dc4a0410d1384172860e844cabfe8cc3172ac0f1c32e7290ca28fe3499a9ac144a1c8918424165a932711e3fccefb3fff4f599d753edc21c2ec005df65da2e66bac24dca69041af231cbaaf6e18c6799731e1bda62a2a774c4adebbb81b1cf87956418b9944a711e3910c26e5e8e60e069eea8c3ed7769c231614a9ca36fb8407b81b5e67c262795fff243869b44358b36510c4e3f46d281d45306fc01eb0975d01e02be17078450085d08007e0f231ee6264896b05a57d0fd5dd167a725de99891c23f05ad9ce891f714e0cdc73d8a1db441195d95e3bbb259a681f63081f3a003020112a281eb0481e8cdc7aeaa51ae78e2adabd140f0c28a21ca527dc6960cbad675564dcd54954ff4bfd96cb95ef7714f21d0c0d5c94f0f0970574488fdd8d519563e0d775607b084170c4959205c4dbc4f16fa0d4099546de7239d64194c92de073a53e2af868e823262926ffc01e488a306fe84e59ad375fea8debf2b864789d275412947508592bd5adac0d2ddf31f7d56be6bd1cf722a3bdae04d7514e8cd9c4460890afb901c75dd6659cced7e84a82446e8779ce5b7e740c61c149982936d37667191b4d0c28daafc66ddb4c71772800217bf1281109da55bda95f32eea02a06d00a87f91e2bdbfbb7906d5a143"
const pa149rep = "6b8202f3308202efa003020105a10302010ba22e302c302aa103020113a2230421301f301da003020112a1161b14544553542e474f4b524235746573747573657231a30d1b0b544553542e474f4b524235a4163014a003020101a10d300b1b09746573747573657231a582015a6182015630820152a003020105a10d1b0b544553542e474f4b524235a220301ea003020102a11730151b066b72627467741b0b544553542e474f4b524235a382011830820114a003020112a103020101a28201060482010237e486e32cd18ab1ac9f8d42e93f8babd7b3497084cc5599f18ec61961c6d5242d350354d99d67a7604c451116188d16cb719e84377212eac2743440e8c504ef69c755e489cc6b65f935dd032bfc076f9b2c56d816197845b8fe857d738bc59712787631a50e86833d1b0e4732c8712c856417a6a257758e7d01d3182adb3233f0dde65d228c240ed26aa1af69f8d765dc0bc69096fdb037a75af220fea176839528d44b70f7dabfaa2ea506de1296f847176a60c501fd8cef8e0a51399bb6d5f753962d96292e93ffe344c6630db912931d46d88c0279f00719e22d0efcfd4ee33a702d0b660c1f13970a9beec12c0c8af3dda68bd81ac1fe3f126d2a24ebb445c5a682012c30820128a003020112a282011f0482011bb149cc16018072c4c18788d95a33aba540e52c11b54a93e67e788d05de75d8f3d4aa1afafbbfa6fde3eb40e5aa1890644cea2607efd5213a3fd00345b02eeb9ae1b589f36c74c689cd4ec1239dfe61e42ba6afa33f6240e3cfab291e4abb465d273302dbf7dbd148a299a9369044dd03377c1687e7dd36aa66501284a4ca50c0a7b08f4f87aecfa23b0dd0b11490e3ad330906dab715de81fc52f120d09c39990b8b5330d4601cc396b2ed258834329c4cc02c563a12de3ef9bf11e946258bc2ab5257f4caa4d443a7daf0fc25f6f531c2fcba88af8ca55c85300997cd05abbea52811fe2d038ba8f62fc8e3bc71ce04362d356ea2e1df8ac55c784c53cfb07817d48e39fe99fc8788040d98209c79dcf044d97e80de9f47824646"

func main() {

	TestTGSReq()
}

func NoPA() {
	//kb, _ := hex.DecodeString(ktab)
	//kt, _ := keytab.Parse(kb)
	rb, _ := hex.DecodeString(noparep)
	var ar messages.ASRep
	err := ar.Unmarshal(rb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unmarshal err: %v\n", err)
	}
	//err = ar.DecryptEncPartWithKeytab(kt)
	cred := credentials.NewCredentials("testuser1")
	cred.WithPassword("passwordvalue")
	err = ar.DecryptEncPart(cred.WithPassword("passwordvalue"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nDecrypt err: %v\n%+v\n", err, ar)
	} else {
		fmt.Fprintf(os.Stdout, "\n\nAS REP decrypted with keytab: %+v\n", ar)
	}
}

func Fast() {
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
	kb, _ := hex.DecodeString(ktab)
	kt, err := keytab.Parse(kb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "KT load err: %v\n\n", err)
	}
	cl := client.NewClientWithKeytab("testuser1", kt)
	rb, err := cl.SendToKDC(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error sending to KDC: %v\n", err)
	}
	var ar messages.ASRep
	ar.Unmarshal(rb)
	cred := credentials.NewCredentials("testuser1")
	cred.WithPassword("passwordvalue")
	err = ar.DecryptEncPart(cred.WithKeytab(kt))
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
		cb, err := crypto.GetIntegrityHash(b, ar.DecryptedEncPart.Key.KeyValue, keyusage.KEY_USAGE_AS_REQ, et)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting checksum PAReqEncPARep: %v\n", err)
		} else {
			fmt.Fprintf(os.Stdout, "AS REQ checksum: %+v\n", cb[:et.GetHMACBitLength()/8])
		}
	}
}

func AS() {
	kb, _ := hex.DecodeString(ktab)
	kt, err := keytab.Parse(kb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "KT load err: %v\n\n", err)
	}
	cl := client.NewClientWithKeytab("testuser1", kt)
	c, err := config.NewConfigFromString(krb5conf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating config: %v", err)
	}
	cl.WithConfig(c)
	fmt.Fprintf(os.Stderr, "Start: %v\n", time.Now())
	err = cl.ASExchange()
	fmt.Fprintf(os.Stderr, "End  : %v\n", time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v", err)
	}
}

func TestTGSReq() {
	b, err := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	cl := client.NewClientWithKeytab("testuser1", kt)
	cl.WithConfig(c)

	err = cl.ASExchange()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error on AS_REQ: %v", err)
	}
	fmt.Fprintf(os.Stderr, "Client: %+v\n", cl)

/*	var a messages.TGSReq
	b, err = hex.DecodeString(testdata.TEST_TGS_REQ)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Test vector read error: %v\n", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unmarshal error: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "TGS_REQ: %+v\n", a)*/

	tgs, err := messages.NewTGSReq("testuser1", c, cl.Session.TGT, cl.Session.SessionKey, "HTTP/host.test.gokrb5")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error on New TGS_REQ: %v", err)
	}
	fmt.Fprintf(os.Stderr, "TGS_REQ gen: %+v\n", tgs)
	b, err = tgs.Marshal()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling TGS_REQ: %v", err)
	}
	_, err = cl.SendToKDC(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error sending TGS_REQ to KDC: %v", err)
	}

}