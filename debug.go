package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"encoding/asn1"
	cpasn1 "github.com/jcmturner/asn1/identicalsrc"

)

type BitStringStruct struct {
	Bs asn1.BitString `asn1:"explicit,tag:0"`
}

func main() {
	var o BitStringStruct
	bs, _ := hex.DecodeString("3009a007030500fedcba90")
	_, e := asn1.Unmarshal(bs, &o)
	if e != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", e)
	} else {
		fmt.Fprintf(os.Stderr, "Bitstring: %+v\n", o)
	}
	n, err := asn1.Marshal(o)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", e)
	}
	c, err := cpasn1.Marshal(o)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", e)
	}
	fmt.Fprintf(os.Stderr, "Input bytes:         %v\nOutput originalasn1: %v\n", bs, n)
	fmt.Fprintf(os.Stderr, "Output copy of asn1: %v\n", c)

}