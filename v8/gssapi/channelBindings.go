// Package gssapi implements Generic Security Services Application Program Interface required for SPNEGO kerberos authentication.
package gssapi

import (
	"crypto/md5"
	"encoding/binary"
)

// AddressType constants for channel bindings (RFC 2744 Section 3.11).
const (
	AddressTypeUnspecified uint32 = 0
	AddressTypeLocal       uint32 = 1
	AddressTypeIPv4        uint32 = 2
	AddressTypeDECnet      uint32 = 12
	AddressTypeIPv6        uint32 = 24
)

// ChannelBindings represents GSS-API channel bindings per RFC 2744 Section 3.11.
// Channel bindings are used to bind the GSS-API security context to the underlying
// transport channel, providing protection against man-in-the-middle attacks.
//
// For TLS channel binding (tls-server-end-point), typically only ApplicationData
// is populated with the TLS channel binding data, while address fields are left empty.
type ChannelBindings struct {
	InitiatorAddrType uint32
	InitiatorAddress  []byte
	AcceptorAddrType  uint32
	AcceptorAddress   []byte
	ApplicationData   []byte
}

// Marshal serializes the channel bindings into the RFC 2744 wire format.
// The format is (all integers are little-endian):
//   - InitiatorAddrType (4 bytes)
//   - InitiatorAddress length (4 bytes)
//   - InitiatorAddress data
//   - AcceptorAddrType (4 bytes)
//   - AcceptorAddress length (4 bytes)
//   - AcceptorAddress data
//   - ApplicationData length (4 bytes)
//   - ApplicationData
func (cb *ChannelBindings) Marshal() []byte {
	// Calculate total size
	size := 4 + 4 + len(cb.InitiatorAddress) +
		4 + 4 + len(cb.AcceptorAddress) +
		4 + len(cb.ApplicationData)

	b := make([]byte, size)
	offset := 0

	// InitiatorAddrType
	binary.LittleEndian.PutUint32(b[offset:offset+4], cb.InitiatorAddrType)
	offset += 4

	// InitiatorAddress length + data
	binary.LittleEndian.PutUint32(b[offset:offset+4], uint32(len(cb.InitiatorAddress)))
	offset += 4
	copy(b[offset:], cb.InitiatorAddress)
	offset += len(cb.InitiatorAddress)

	// AcceptorAddrType
	binary.LittleEndian.PutUint32(b[offset:offset+4], cb.AcceptorAddrType)
	offset += 4

	// AcceptorAddress length + data
	binary.LittleEndian.PutUint32(b[offset:offset+4], uint32(len(cb.AcceptorAddress)))
	offset += 4
	copy(b[offset:], cb.AcceptorAddress)
	offset += len(cb.AcceptorAddress)

	// ApplicationData length + data
	binary.LittleEndian.PutUint32(b[offset:offset+4], uint32(len(cb.ApplicationData)))
	offset += 4
	copy(b[offset:], cb.ApplicationData)

	return b
}

// MD5Hash computes the MD5 hash of the serialized channel bindings.
// This is the "Bnd" value used in the GSS-API authenticator checksum (RFC 4121 Section 4.1.1).
// The hash is placed in bytes 4-19 of the authenticator checksum when channel bindings are present.
func (cb *ChannelBindings) MD5Hash() [16]byte {
	return md5.Sum(cb.Marshal())
}
