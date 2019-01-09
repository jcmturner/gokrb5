package service

import (
	"log"

	"gopkg.in/jcmturner/gokrb5.v6/keytab"
	"gopkg.in/jcmturner/gokrb5.v6/types"
)

type Settings struct {
	Keytab             *keytab.Keytab
	spn                types.PrincipalName
	requireHostAddr    bool
	disablePACDecoding bool
	cAddr              types.HostAddress
	logger             *log.Logger
}

func NewSettings(kt *keytab.Keytab, options ...func(*Settings)) *Settings {
	s := new(Settings)
	s.Keytab = kt
	for _, option := range options {
		option(s)
	}
	return s
}

// RequireHostAddr used to configure service side to required host addresses to be specified in Kerberos tickets.
//
// s := NewSettings(kt, RequireHostAddr(true))
func RequireHostAddr(b bool) func(*Settings) {
	return func(s *Settings) {
		s.requireHostAddr = b
	}
}

func (s *Settings) RequireHostAddr() bool {
	return s.requireHostAddr
}

// DecodePAC used to configure service side to enable/disable PAC decoding if the PAC is present.
// Defaults to enabled if not specified.
//
// s := NewSettings(kt, DecodePAC(false))
func DecodePAC(b bool) func(*Settings) {
	return func(s *Settings) {
		s.disablePACDecoding = !b
	}
}

func (s *Settings) DecodePAC() bool {
	return !s.disablePACDecoding
}

// ClientAddress used to configure service side with the clients host address to be used during validation.
//
// s := NewSettings(kt, ClientAddress(h))
func ClientAddress(h types.HostAddress) func(*Settings) {
	return func(s *Settings) {
		s.cAddr = h
	}
}

func (s *Settings) ClientAddress() types.HostAddress {
	return s.cAddr
}

// Logger used to configure service side with a logger.
//
// s := NewSettings(kt, Logger(l))
func Logger(l *log.Logger) func(*Settings) {
	return func(s *Settings) {
		s.logger = l
	}
}

func (s *Settings) Logger() *log.Logger {
	return s.logger
}

// SPN used to configure service side with a specific SPN.
//
// s := NewSettings(kt, SPN(spn))
func SPN(spn types.PrincipalName) func(*Settings) {
	return func(s *Settings) {
		s.spn = spn
	}
}

func (s *Settings) SPN() types.PrincipalName {
	return s.spn
}
