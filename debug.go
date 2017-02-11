package main

import (
	"encoding/hex"
	"fmt"
	"github.com/jcmturner/gokrb5/keytab"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/types"
	"net"
	"os"
	"time"
)

const ktab = "05020000004b0001000b544553542e474f4b5242350009746573747573657231000000015898e0770100120020bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de900000001"

func main() {
	udpAddr, _ := net.ResolveUDPAddr("udp", "10.80.88.88:88")
	realm := "TEST.GOKRB5"

	conn, _ := net.DialUDP("udp", nil, udpAddr)
	defer conn.Close()

	var pas types.PADataSequence
	pa := types.PAData{
		PADataType: 149,
	}
	pas = append(pas, pa)

	a := messages.NewASReq()
	a.PAData = pas
	a.ReqBody.Realm = realm
	a.ReqBody.CName.NameString = []string{"testuser1"}
	a.ReqBody.SName.NameType = 2
	a.ReqBody.SName.NameString = []string{"krbtgt", realm}
	a.ReqBody.Till = time.Now().Add(10 * time.Hour)
	a.ReqBody.Nonce = 2069991465
	a.ReqBody.EType = []int{18}
	fmt.Fprintf(os.Stdout, "AS_REQ: %+v\n", a)
	b, err := a.Marshal()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling AS_REQ: %v\n", err)
	}

	_, _ = conn.Write(b)

	buf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(buf)
	var r messages.ASRep
	var p messages.ASRep
	r.Unmarshal(buf[:n])
	p.Unmarshal(buf[:n])
	fmt.Fprintf(os.Stdout, "AS_REP: %+v\n", r)

	kb, _ := hex.DecodeString(ktab)
	kt, err := keytab.Parse(kb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "KT load err: %v\n\n", err)
	}
	fmt.Fprintf(os.Stdout, "KT: %+v", kt)
	err = r.DecryptEncPartWithKeytab(kt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nDecrypt err: %v\n", err)
	} else {
		fmt.Fprintf(os.Stdout, "\n\nAS REP decrypted with keytab: %+v\n", r)
	}

	pswd := "passwordvalue"
	err = p.DecryptEncPartWithPassword(pswd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nDecrypt err: %v\n", err)
	} else {
		fmt.Fprintf(os.Stdout, "\nAS REP decrypted with passwd: %+v\n", p)
	}
}
