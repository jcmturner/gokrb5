// Error handling.
package krberror

import (
	"fmt"
	"strings"
)

const (
	SEPARATOR        = " < "
	ENCODING_ERROR   = "Encoding_Error"
	NETWORKING_ERROR = "Networking_Error"
	DECRYPTING_ERROR = "Decrypting_Error"
	ENCRYPTING_ERROR = "Encrypting_Error"
	CHKSUM_ERROR     = "Checksum_Error"
	KRBMSG_ERROR     = "KRBMessage_Handling_Error"
)

type krberror struct {
	RootCause string
	EText     []string
}

func (e krberror) Error() string {
	return fmt.Sprintf("[Root cause: %s] ", e.RootCause) + strings.Join(e.EText, SEPARATOR)
}

func (e *krberror) Add2(et string, s string) {
	e.EText = append([]string{fmt.Sprintf("%s: %s", et, s)}, e.EText...)
}

func NewKrberror(et, s string) krberror {
	return krberror{
		RootCause: et,
		EText:     []string{s},
	}
}

func Errorf(err error, et, format string, a ...interface{}) krberror {
	if e, ok := err.(krberror); ok {
		e.EText = append([]string{fmt.Sprintf("%s: "+format, et, a)}, e.EText...)
		return e
	} else {
		return NewErrorf(et, format+": %v", a, err)
	}
}

func NewErrorf(et, format string, a ...interface{}) krberror {
	return krberror{
		RootCause: et,
		EText:     []string{fmt.Sprintf("%s: %s", et, fmt.Sprintf(format, a))},
	}
}
