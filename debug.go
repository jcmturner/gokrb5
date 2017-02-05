package main

import (
	"net"
	"github.com/jcmturner/gokrb5/messages"
	"time"
	"fmt"
	"os"
)

func main() {
	udpAddr, _ := net.ResolveUDPAddr("udp", "10.80.88.88:88")
	realm := "TEST.GOKRB5"

	conn, _ := net.DialUDP("udp", nil, udpAddr)
	defer conn.Close()

	a := messages.NewASReq()
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
	var m messages.ASReq
	m.Unmarshal(b)
	b, err = m.Marshal()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling AS_REQ: %v\n", err)
	}
	fmt.Fprintf(os.Stdout, "AS_REQ post marshal: %+v\n", m)
	_, _ = conn.Write(b)


	buf := make([]byte, 4096)
	n,_,err := conn.ReadFrom(buf)

	var r messages.ASRep
	r.Unmarshal(buf[:n])
	fmt.Fprintf(os.Stdout, "AS REP: %+v\n", r)



}
