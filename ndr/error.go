package ndr

import "fmt"

type Malformed struct {
	EText string
}

func (e Malformed) Error() string {
	return fmt.Sprintf("Malformed NDR steam: %s", e.EText)
}
