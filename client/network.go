package client

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/jcmturner/gokrb5/iana/errorcode"
	"github.com/jcmturner/gokrb5/messages"
	"io"
	"math/rand"
	"net"
	"time"
)

// SendToKDC performs network actions to send data to the KDC.
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
			if e, ok := errtcp.(messages.KRBError); ok {
				return rb, e
			}
			return rb, fmt.Errorf("Failed to communicate with KDC %v via TCP (%v)", kdc, errtcp)
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
			if e, ok := errudp.(messages.KRBError); ok && e.ErrorCode != errorcode.KRB_ERR_RESPONSE_TOO_BIG {
				// Got a KRBError from KDC
				// If this is not a KRB_ERR_RESPONSE_TOO_BIG we will return immediately otherwise will try TCP.
				return rb, e
			}
			// Try TCP
			r, errtcp := sendTCP(kdc, b)
			if errtcp != nil {
				if e, ok := errtcp.(messages.KRBError); ok {
					// Got a KRBError
					return r, e
				}
				return r, fmt.Errorf("Failed to communicate with KDC %v. Attempts made with UDP (%v) and then TCP (%v)", kdc, errudp, errtcp)
			}
			rb = r
		}
		if len(rb) < 1 {
			return rb, fmt.Errorf("No response data from KDC %v", kdc)
		}
		return rb, nil
	}
	//Try TCP first, UDP second
	rb, errtcp := sendTCP(kdc, b)
	if errtcp != nil {
		if e, ok := errtcp.(messages.KRBError); ok {
			// Got a KRBError from KDC so returning and not trying UDP.
			return rb, e
		}
		rb, errudp := sendUDP(kdc, b)
		if errudp != nil {
			if e, ok := errudp.(messages.KRBError); ok {
				// Got a KRBError
				return rb, e
			}
			return rb, fmt.Errorf("Failed to communicate with KDC %v. Attempts made with TCP (%v) and then UDP (%v)", kdc, errtcp, errudp)
		}
	}
	if len(rb) < 1 {
		return rb, fmt.Errorf("No response data from KDC %v", kdc)
	}
	return rb, nil
}

// Send the bytes to the KDC over UDP.
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
	return checkForKRBError(r)
}

// Send the bytes to the KDC over TCP.
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

	/*
		RFC https://tools.ietf.org/html/rfc4120#section-7.2.2
		Each request (KRB_KDC_REQ) and response (KRB_KDC_REP or KRB_ERROR)
		sent over the TCP stream is preceded by the length of the request as
		4 octets in network byte order.  The high bit of the length is
		reserved for future expansion and MUST currently be set to zero.  If
		a KDC that does not understand how to interpret a set high bit of the
		length encoding receives a request with the high order bit of the
		length set, it MUST return a KRB-ERROR message with the error
		KRB_ERR_FIELD_TOOLONG and MUST close the TCP stream.
		NB: network byte order == big endian
	*/
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(len(b)))
	b = append(buf.Bytes(), b...)

	_, err = conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("Error sending to KDC: %v", err)
	}
	var rBuf bytes.Buffer
	io.Copy(&rBuf, conn)
	r = rBuf.Bytes()
	return checkForKRBError(r[4:])
}

func checkForKRBError(b []byte) ([]byte, error) {
	var KRBErr messages.KRBError
	if err := KRBErr.Unmarshal(b); err == nil {
		return b, KRBErr
	}
	return b, nil
}
