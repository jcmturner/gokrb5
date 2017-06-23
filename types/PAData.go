package types

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.2.7
import (
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/iana/patype"
	"time"
)

type PAData struct {
	PADataType  int    `asn1:"explicit,tag:1"`
	PADataValue []byte `asn1:"explicit,tag:2"`
}

type PADataSequence []PAData

type MethodData []PAData

type PAEncTimestamp EncryptedData

type PAEncTSEnc struct {
	PATimestamp time.Time `asn1:"generalized,explicit,tag:0"`
	PAUSec      int       `asn1:"explicit,optional,tag:1"`
}

func (pas *PADataSequence) Contains(patype int) bool {
	for _, pa := range *pas {
		if pa.PADataType == patype {
			return true
		}
	}
	return false
}

func GetPAEncTSEncAsnMarshalled() ([]byte, error) {
	t := time.Now().UTC()
	p := PAEncTSEnc{
		PATimestamp: t,
		PAUSec:      int((t.UnixNano() / int64(time.Microsecond)) - (t.Unix() * 1e6)),
	}
	b, err := asn1.Marshal(p)
	if err != nil {
		return b, fmt.Errorf("Error mashaling PAEncTSEnc: %v", err)
	}
	return b, nil
}

type ETypeInfoEntry struct {
	EType int    `asn1:"explicit,tag:0"`
	Salt  []byte `asn1:"explicit,optional,tag:1"`
}

type ETypeInfo []ETypeInfoEntry

type ETypeInfo2Entry struct {
	EType     int    `asn1:"explicit,tag:0"`
	Salt      string `asn1:"explicit,optional,generalstring,tag:1"`
	S2KParams []byte `asn1:"explicit,optional,tag:2"`
}

type ETypeInfo2 []ETypeInfo2Entry

type PAReqEncPARep struct {
	ChksumType int    `asn1:"explicit,tag:0"`
	Chksum     []byte `asn1:"explicit,tag:1"`
}

func (pa *PAData) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, pa)
	return err
}

func (pas *PADataSequence) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, pas)
	return err
}

func (pa *PAReqEncPARep) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, pa)
	return err
}

func (pa *PAEncTimestamp) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, pa)
	return err
}

func (pa *PAEncTSEnc) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, pa)
	return err
}

func (a *ETypeInfo) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}

func (a *ETypeInfoEntry) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}

func (a *ETypeInfo2) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}

func (a *ETypeInfo2Entry) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}

func (pa *PAData) GetETypeInfo() (d ETypeInfo, err error) {
	if pa.PADataType != patype.PA_ETYPE_INFO {
		err = fmt.Errorf("PAData does not contain PA EType Info data. TypeID Expected: %v; Actual: %v", patype.PA_ETYPE_INFO, pa.PADataType)
		return
	}
	_, err = asn1.Unmarshal(pa.PADataValue, &d)
	return
}

func (pa *PAData) GetETypeInfo2() (d ETypeInfo2, err error) {
	if pa.PADataType != patype.PA_ETYPE_INFO2 {
		err = fmt.Errorf("PAData does not contain PA EType Info 2 data. TypeID Expected: %v; Actual: %v", patype.PA_ETYPE_INFO2, pa.PADataType)
		return
	}
	_, err = asn1.Unmarshal(pa.PADataValue, &d)
	return
}
