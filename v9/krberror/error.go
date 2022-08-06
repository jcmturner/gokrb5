// Package krberror provides error types and functions for gokrb5.
package krberror

import (
	"errors"
	"fmt"
	"strings"
)

// Error classification descriptions.
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

// KRBError defines the interface for the gokrb5 error type.
type KRBError interface {
	Error() string
	String() string
	Unwrap() error
	RootCause() KRBError
	Class() string
	Wrap(err error)
}

// Errorf wraps an error in a new KRBError created from the provided function with the specified error text.
func Errorf(err error, krberr func(format string, a ...interface{}) KRBError, format string, a ...interface{}) KRBError {
	e := krberr(format, a...)
	e.Wrap(err)
	return e
}

// EncodingError implements the KRBError interface for message encoding related errors.
type EncodingError struct {
	KRBError
}

// Class returns a descriptive string for the classification of the KRBError.
func (e *EncodingError) Class() string {
	return encodingErrorClass
}

// As implements the method required for the errors.As() function.
func (e *EncodingError) As(target interface{}) bool {
	if t, ok := target.(*EncodingError); ok {
		t.KRBError = e.KRBError
		return true
	}
	return false
}

// EncodingErrorf creates a new EncodingError type KRBError with the error text provided.
func EncodingErrorf(format string, a ...interface{}) KRBError {
	e := &EncodingError{}
	e.KRBError = &krberror{
		etext:   fmt.Sprintf(format, a...),
		rooterr: e,
	}
	return e
}

// NetworkingError implements the KRBError interface for networking related errors.
type NetworkingError struct {
	KRBError
}

// Class returns a descriptive string for the classification of the KRBError.
func (e *NetworkingError) Class() string {
	return networkingErrorClass
}

// As implements the method required for the errors.As() function.
func (e *NetworkingError) As(target interface{}) bool {
	if t, ok := target.(*NetworkingError); ok {
		t.KRBError = e.KRBError
		return true
	}
	return false
}

// NetworkingErrorf creates a new NetworkingError type KRBError with the error text provided.
func NetworkingErrorf(format string, a ...interface{}) KRBError {
	e := &NetworkingError{}
	e.KRBError = &krberror{
		etext:   fmt.Sprintf(format, a...),
		rooterr: e,
	}
	return e
}

// DecryptingError implements the KRBError interface for decrypting related errors.
type DecryptingError struct {
	KRBError
}

// Class returns a descriptive string for the classification of the KRBError.
func (e *DecryptingError) Class() string {
	return decryptingErrorClass
}

// As implements the method required for the errors.As() function.
func (e *DecryptingError) As(target interface{}) bool {
	if t, ok := target.(*DecryptingError); ok {
		t.KRBError = e.KRBError
		return true
	}
	return false
}

// DecryptingErrorf creates a new DecryptingError type KRBError with the error text provided.
func DecryptingErrorf(format string, a ...interface{}) KRBError {
	e := &DecryptingError{}
	e.KRBError = &krberror{
		etext:   fmt.Sprintf(format, a...),
		rooterr: e,
	}
	return e
}

// EncryptingError implements the KRBError interface for encrypting related errors.
type EncryptingError struct {
	KRBError
}

// Class returns a descriptive string for the classification of the KRBError.
func (e *EncryptingError) Class() string {
	return encryptingErrorClass
}

// As implements the method required for the errors.As() function.
func (e *EncryptingError) As(target interface{}) bool {
	if t, ok := target.(*EncryptingError); ok {
		t.KRBError = e.KRBError
		return true
	}
	return false
}

// EncryptingErrorf creates a new EncryptingError type KRBError with the error text provided.
func EncryptingErrorf(format string, a ...interface{}) KRBError {
	e := &EncryptingError{}
	e.KRBError = &krberror{
		etext:   fmt.Sprintf(format, a...),
		rooterr: e,
	}
	return e
}

// ChksumError implements the KRBError interface for checksum validation errors.
type ChksumError struct {
	KRBError
}

// Class returns a descriptive string for the classification of the KRBError.
func (e *ChksumError) Class() string {
	return chksumErrorClass
}

// As implements the method required for the errors.As() function.
func (e *ChksumError) As(target interface{}) bool {
	if t, ok := target.(*ChksumError); ok {
		t.KRBError = e.KRBError
		return true
	}
	return false
}

// ChksumErrorf creates a new ChksumError type KRBError with the error text provided.
func ChksumErrorf(format string, a ...interface{}) KRBError {
	e := &ChksumError{}
	e.KRBError = &krberror{
		etext:   fmt.Sprintf(format, a...),
		rooterr: e,
	}
	return e
}

// KRBMsgError implements the KRBError interface for kerberos message formation and processing related errors.
type KRBMsgError struct {
	KRBError
}

// Class returns a descriptive string for the classification of the KRBError.
func (e *KRBMsgError) Class() string {
	return krbMsgErrorClass
}

// As implements the method required for the errors.As() function.
func (e *KRBMsgError) As(target interface{}) bool {
	if t, ok := target.(*KRBMsgError); ok {
		t.KRBError = e.KRBError
		return true
	}
	return false
}

// KRBMsgErrorf creates a new KRBMsgError type KRBError with the error text provided.
func KRBMsgErrorf(format string, a ...interface{}) KRBError {
	e := &KRBMsgError{}
	e.KRBError = &krberror{
		etext:   fmt.Sprintf(format, a...),
		rooterr: e,
	}
	return e
}

// ConfigError implements the KRBError interface for configuration related errors.
type ConfigError struct {
	KRBError
}

// Class returns a descriptive string for the classification of the KRBError.
func (e *ConfigError) Class() string {
	return configErrorClass
}

// As implements the method required for the errors.As() function.
func (e *ConfigError) As(target interface{}) bool {
	if t, ok := target.(*ConfigError); ok {
		t.KRBError = e.KRBError
		return true
	}
	return false
}

// ConfigErrorf creates a new ConfigError type KRBError with the error text provided.
func ConfigErrorf(format string, a ...interface{}) KRBError {
	e := &ConfigError{}
	e.KRBError = &krberror{
		etext:   fmt.Sprintf(format, a...),
		rooterr: e,
	}
	return e
}

// KDCError implements the KRBError interface for errors originating from the KDC.
type KDCError struct {
	KRBError
}

// Class returns a descriptive string for the classification of the KRBError.
func (e *KDCError) Class() string {
	return kdcErrorClass
}

// As implements the method required for the errors.As() function.
func (e *KDCError) As(target interface{}) bool {
	if t, ok := target.(*KDCError); ok {
		t.KRBError = e.KRBError
		return true
	}
	return false
}

// KDCErrorf creates a new KDCError type KRBError with the error text provided.
func KDCErrorf(format string, a ...interface{}) KRBError {
	e := &KDCError{}
	e.KRBError = &krberror{
		etext:   fmt.Sprintf(format, a...),
		rooterr: e,
	}
	return e
}

// krberror implements the KRBError interface and is used by other error types to implement common methods of the
// interface.
type krberror struct {
	etext   string
	inner   error
	rooterr KRBError
}

// String returns the error text without recusing into wrapped errors.
func (e *krberror) String() string {
	return e.etext
}

// Wrap the provided error with the KRBError receiver of this method.
func (e *krberror) Wrap(err error) {
	e.inner = err
	if krberr, ok := err.(KRBError); ok {
		e.rooterr = krberr.RootCause()
		return
	}
}

// Unwrap returns any error wrapped within the KRBError receiver of this method.
func (e *krberror) Unwrap() error {
	return e.inner
}

// RootCause returns the inner most wrapped error that is a KRBError.
func (e *krberror) RootCause() KRBError {
	return e.rooterr
}

// Class returns a descriptive string for the classification of the KRBError.
func (e *krberror) Class() string {
	return unclassifiedErrorClass
}

// Error returns a string combining the error texts of all wrapped KRBErrors.
func (e *krberror) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Root cause: %s] %s", e.RootCause().Class(), e.String())
	i := e.Unwrap()
	for i != nil {
		if err, ok := isKRBError(i); ok {
			fmt.Fprintf(&b, separator, err.String())
		} else {
			fmt.Fprintf(&b, separator, i.Error())
		}
		i = errors.Unwrap(i)
	}
	return b.String()
}

// isKRBError indicates if the provided error is one of the KRBError types.
func isKRBError(err error) (KRBError, bool) {
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
