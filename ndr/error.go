package ndr

import "fmt"

type NDRMalformed struct {
	EText string
}

func (e NDRMalformed) Error() string {
	return fmt.Sprintf("Malformed NDR steam: %s", e.EText)
}
