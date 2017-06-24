package ndr

import "fmt"

type Malformed struct {
	EText string
}

// Error implements the error interface on the Malformed struct.
func (e Malformed) Error() string {
	return fmt.Sprintf("Malformed NDR steam: %s", e.EText)
}
