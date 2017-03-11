package client

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// Send bytes to the KDC
func (cl *Client) SendToKDC(b []byte) ([]byte, error) {
	var rb []byte
	var kdcs []string
	for _, r := range cl.Config.Realms {
		if r.Realm == cl.Config.LibDefaults.Default_realm {
			kdcs = r.Kdc
			break
		}
	}
	if len(kdcs) < 1 {
		return rb, fmt.Errorf("No KDCs defined in configuration for realm: %v", cl.Config.LibDefaults.Default_realm)
	}
	var kdc string
	if len(kdcs) > 1 {
		//Select one of the KDCs at random
		kdc = kdcs[rand.Intn(len(kdcs))]
	} else {
		kdc = kdcs[0]
	}

	if cl.Config.LibDefaults.Udp_preference_limit == 1 {
		//1 means we should always use TCP
		rb, errtcp := sendTCP(kdc, b)
		if errtcp != nil {
			return rb, fmt.Errorf("Failed to communicate with KDC %v via TDP (%v)", kdc, errtcp)
		}
		if len(rb) < 1 {
			return rb, fmt.Errorf("No response data from KDC %v", kdc)
		}
		return rb, nil
	}
	if len(b) <= cl.Config.LibDefaults.Udp_preference_limit {
		//Try UDP first, TCP second
		rb, errudp := sendUDP(kdc, b)
		if errudp != nil {
			rb, errtcp := sendTCP(kdc, b)
			if errtcp != nil {
				return rb, fmt.Errorf("Failed to communicate with KDC %v via UDP (%v) and then via TDP (%v)", kdc, errudp, errtcp)
			}
		}
		if len(rb) < 1 {
			return rb, fmt.Errorf("No response data from KDC %v", kdc)
		}
		return rb, nil
	}
	//Try TCP first, UDP second
	rb, errtcp := sendTCP(kdc, b)
	if errtcp != nil {
		rb, errudp := sendUDP(kdc, b)
		if errudp != nil {
			return rb, fmt.Errorf("Failed to communicate with KDC %v via TCP (%v) and then via UDP (%v)", kdc, errtcp, errudp)
		}
	}
	if len(rb) < 1 {
		return rb, fmt.Errorf("No response data from KDC %v", kdc)
	}
	return rb, nil
}

// Send the bytes to the KDC over UDP
func sendUDP(kdc string, b []byte) ([]byte, error) {
	var r []byte
	udpAddr, err := net.ResolveUDPAddr("udp", kdc)
	if err != nil {
		return r, fmt.Errorf("Error resolving KDC address: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return r, fmt.Errorf("Error establishing connection to KDC: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(5 * time.Second)))
	_, err = conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("Error sending to KDC: %v", err)
	}
	udpbuf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(udpbuf)
	r = udpbuf[:n]
	if err != nil {
		return r, fmt.Errorf("Sending over UDP failed: %v", err)
	}
	return r, nil
}

// Send the bytes to the KDC over TCP
func sendTCP(kdc string, b []byte) ([]byte, error) {
	var r []byte
	tcpAddr, err := net.ResolveTCPAddr("tcp", kdc)
	if err != nil {
		return r, fmt.Errorf("Error resolving KDC address: %v", err)
	}
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return r, fmt.Errorf("Error establishing connection to KDC: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(5 * time.Second)))
	_, err = conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("Error sending to KDC: %v", err)
	}
	tcpbuf := bytes.NewBuffer(make([]byte, 4096))
	n, err := conn.ReadFrom(tcpbuf)
	r = tcpbuf.Bytes()[:n]
	if err != nil {
		return r, fmt.Errorf("Sending over TCP failed: %v", err)
	}
	return r, nil
}
