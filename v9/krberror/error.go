// Package krberror provides error types and functions for gokrb5.
package krberror

import (
	"errors"
	"fmt"
	"strings"
)

// Error type descriptions.
const (
	separator              = " < %s"
	encodingErrorClass     = "Encoding_Error"
	networkingErrorClass   = "Networking_Error"
	decryptingErrorClass   = "Decrypting_Error"
	encryptingErrorClass   = "Encrypting_Error"
	chksumErrorClass       = "Checksum_Error"
	krbMsgErrorClass       = "KRBMessage_Handling_Error"
	configErrorClass       = "Configuration_Error"
	kdcErrorClass          = "KDC_Error"
	unclassifiedErrorClass = "Unclassified_Error"
)

type Krberror interface {
	Error() string
	String() string
	Unwrap() error
	RootCause() Krberror
	Class() string
	Wrap(err error)
}

// Errorf appends to or creates a new Krberror.
func Errorf(err error, krberr func(format string, a ...interface{}) Krberror, format string, a ...interface{}) Krberror {
	e := krberr(format, a...)
	e.Wrap(err)
	return e
}

type EncodingError struct {
	Krberror
}

func (e *EncodingError) Class() string {
	return encodingErrorClass
}

func (e *EncodingError) As(target interface{}) bool {
	if t, ok := target.(*EncodingError); ok {
		t.Krberror = e.Krberror
		return true
	}
	return false
}

func EncodingErrorf(format string, a ...interface{}) Krberror {
	e := &EncodingError{}
	e.Krberror = &krberror{
		etext:   fmt.Sprintf(format, a...),
		rooterr: e,
	}
	return e
}

type NetworkingError struct {
	Krberror
}

func (e *NetworkingError) Class() string {
	return networkingErrorClass
}

func (e *NetworkingError) As(target interface{}) bool {
	if t, ok := target.(*NetworkingError); ok {
		t.Krberror = e.Krberror
		return true
	}
	return false
}

func NetworkingErrorf(format string, a ...interface{}) Krberror {
	e := &NetworkingError{}
	e.Krberror = &krberror{
		etext:   fmt.Sprintf(format, a...),
		rooterr: e,
	}
	return e
}

type DecryptingError struct {
	Krberror
}

func (e *DecryptingError) Class() string {
	return decryptingErrorClass
}

func (e *DecryptingError) As(target interface{}) bool {
	if t, ok := target.(*DecryptingError); ok {
		t.Krberror = e.Krberror
		return true
	}
	return false
}

func DecryptingErrorf(format string, a ...interface{}) Krberror {
	e := &DecryptingError{}
	e.Krberror = &krberror{
		etext:   fmt.Sprintf(format, a...),
		rooterr: e,
	}
	return e
}

type EncryptingError struct {
	Krberror
}

func (e *EncryptingError) Class() string {
	return encryptingErrorClass
}

func (e *EncryptingError) As(target interface{}) bool {
	if t, ok := target.(*EncryptingError); ok {
		t.Krberror = e.Krberror
		return true
	}
	return false
}

func EncryptingErrorf(format string, a ...interface{}) Krberror {
	e := &EncryptingError{}
	e.Krberror = &krberror{
		etext:   fmt.Sprintf(format, a...),
		rooterr: e,
	}
	return e
}

type ChksumError struct {
	Krberror
}

func (e *ChksumError) Class() string {
	return chksumErrorClass
}

func (e *ChksumError) As(target interface{}) bool {
	if t, ok := target.(*ChksumError); ok {
		t.Krberror = e.Krberror
		return true
	}
	return false
}

func ChksumErrorf(format string, a ...interface{}) Krberror {
	e := &ChksumError{}
	e.Krberror = &krberror{
		etext:   fmt.Sprintf(format, a...),
		rooterr: e,
	}
	return e
}

type KRBMsgError struct {
	Krberror
}

func (e *KRBMsgError) Class() string {
	return krbMsgErrorClass
}

func (e *KRBMsgError) As(target interface{}) bool {
	if t, ok := target.(*KRBMsgError); ok {
		t.Krberror = e.Krberror
		return true
	}
	return false
}

func KRBMsgErrorf(format string, a ...interface{}) Krberror {
	e := &KRBMsgError{}
	e.Krberror = &krberror{
		etext:   fmt.Sprintf(format, a...),
		rooterr: e,
	}
	return e
}

type ConfigError struct {
	Krberror
}

func (e *ConfigError) Class() string {
	return configErrorClass
}

func (e *ConfigError) As(target interface{}) bool {
	if t, ok := target.(*ConfigError); ok {
		t.Krberror = e.Krberror
		return true
	}
	return false
}

func ConfigErrorf(format string, a ...interface{}) Krberror {
	e := &ConfigError{}
	e.Krberror = &krberror{
		etext:   fmt.Sprintf(format, a...),
		rooterr: e,
	}
	return e
}

type KDCError struct {
	Krberror
}

func (e *KDCError) Class() string {
	return kdcErrorClass
}

func (e *KDCError) As(target interface{}) bool {
	if t, ok := target.(*KDCError); ok {
		t.Krberror = e.Krberror
		return true
	}
	return false
}

func KDCErrorf(format string, a ...interface{}) Krberror {
	e := &KDCError{}
	e.Krberror = &krberror{
		etext:   fmt.Sprintf(format, a...),
		rooterr: e,
	}
	return e
}

type krberror struct {
	etext   string
	inner   error
	rooterr Krberror
}

func (e *krberror) String() string {
	return e.etext
}

func (e *krberror) Wrap(err error) {
	e.inner = err
	if krberr, ok := err.(Krberror); ok {
		e.rooterr = krberr.RootCause()
		return
	}
}

func (e *krberror) Unwrap() error {
	return e.inner
}

func (e *krberror) RootCause() Krberror {
	return e.rooterr
}

func (e *krberror) Class() string {
	return unclassifiedErrorClass
}

func (e *krberror) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Root cause: %s] %s", e.RootCause().Class(), e.String())
	i := e.Unwrap()
	for i != nil {
		if err, ok := isKrbError(i); ok {
			fmt.Fprintf(&b, separator, err.String())
		} else {
			fmt.Fprintf(&b, separator, i.Error())
		}
		i = errors.Unwrap(i)
	}
	return b.String()
}

func isKrbError(err error) (Krberror, bool) {
	switch v := err.(type) {
	case *EncodingError:
		return v, true
	case *NetworkingError:
		return v, true
	case *DecryptingError:
		return v, true
	case *EncryptingError:
		return v, true
	case *ChksumError:
		return v, true
	case *KRBMsgError:
		return v, true
	case *ConfigError:
		return v, true
	case *KDCError:
		return v, true
	default:
		return nil, false
	}
}
