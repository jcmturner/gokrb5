package types

import "encoding/asn1"

type TypedData struct {
	DataType  int    `asn1:"explicit,tag:0"`
	DataValue []byte `asn1:"optional,explicit,tag:1"`
}

type TypedDataSequence []TypedData

func (a *TypedDataSequence) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}