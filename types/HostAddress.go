package types

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.2.5

import (
	"encoding/asn1"
)

/*
HostAddress and HostAddresses

HostAddress     ::= SEQUENCE  {
	addr-type       [0] Int32,
	address         [1] OCTET STRING
}

-- NOTE: HostAddresses is always used as an OPTIONAL field and
-- should not be empty.
HostAddresses   -- NOTE: subtly different from rfc1510,
		-- but has a value mapping and encodes the same
	::= SEQUENCE OF HostAddress

The host address encodings consist of two fields:

addr-type
	This field specifies the type of address that follows.  Pre-
	defined values for this field are specified in Section 7.5.3.

address
	This field encodes a single address of type addr-type.
*/

type HostAddresses []HostAddress

type HostAddress struct {
	AddrType int    `asn1:"explicit,tag:0"`
	Address  []byte `asn1:"explicit,tag:1"`
}

func (h *HostAddress) GetAddress() (string, error) {
	var b []byte
	_, err := asn1.Unmarshal(h.Address, &b)
	return string(b), err
}
