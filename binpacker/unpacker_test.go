package binpacker

import (
	"bytes"
	"io"
	"testing"

	"math"

	"github.com/stretchr/testify/assert"
	"encoding/binary"
)

// TestReader wraps a []byte and returns reads of a specific length.
// slightly modified version of one in https://golang.org/src/bufio/bufio_test.go
type testReader struct {
	data   []byte
	stride int
}

func (t *testReader) Read(buf []byte) (n int, err error) {
	n = t.stride
	if n > len(t.data) {
		n = len(t.data)
	}
	if n > len(buf) {
		n = len(buf)
	}
	copy(buf, t.data[:n])
	t.data = t.data[n:]
	if len(t.data) == 0 {
		err = io.EOF
	}
	return
}

func TestShiftByte(t *testing.T) {
	buf := new(bytes.Buffer)
	p := NewPacker(binary.BigEndian, buf)
	u := NewUnpacker(binary.BigEndian, buf)
	p.PushByte(0x01)
	b, err := u.ShiftByte()
	assert.Equal(t, err, nil, "Has error.")
	assert.Equal(t, b, byte(0x01), "byte error.")
}

func TestShiftBytes(t *testing.T) {
	reader := &testReader{
		data:   []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		stride: 2,
	}

	u := NewUnpacker(binary.BigEndian, reader)
	bs, err := u.ShiftBytes(5)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04, 0x05}, bs, "byte error.")
}

func TestShiftUint8(t *testing.T) {
	buf := new(bytes.Buffer)
	p := NewPacker(binary.BigEndian, buf)
	u := NewUnpacker(binary.BigEndian, buf)
	p.PushUint8(1)
	i, err := u.ShiftUint8()
	assert.Equal(t, err, nil, "Has error.")
	assert.Equal(t, i, uint8(1), "uint16 error.")
}

func TestShiftUint16(t *testing.T) {
	buf := new(bytes.Buffer)
	p := NewPacker(binary.BigEndian, buf)
	u := NewUnpacker(binary.BigEndian, buf)
	p.PushUint16(1)
	i, err := u.ShiftUint16()
	assert.Equal(t, err, nil, "Has error.")
	assert.Equal(t, i, uint16(1), "uint16 error.")
}

func TestShiftInt16(t *testing.T) {
	buf := new(bytes.Buffer)
	p := NewPacker(binary.BigEndian, buf)
	u := NewUnpacker(binary.BigEndian, buf)
	p.PushInt16(-1)
	i, err := u.ShiftInt16()
	assert.Equal(t, err, nil, "Has error.")
	assert.Equal(t, i, int16(-1), "uint16 error.")
}

func TestShiftUint32(t *testing.T) {
	buf := new(bytes.Buffer)
	p := NewPacker(binary.BigEndian, buf)
	u := NewUnpacker(binary.BigEndian, buf)
	p.PushUint32(1)
	i, err := u.ShiftUint32()
	assert.Equal(t, err, nil, "Has error.")
	assert.Equal(t, i, uint32(1), "uint32 error.")
}

func TestShiftInt32(t *testing.T) {
	buf := new(bytes.Buffer)
	p := NewPacker(binary.BigEndian, buf)
	u := NewUnpacker(binary.BigEndian, buf)
	p.PushInt32(-1)
	i, err := u.ShiftInt32()
	assert.Equal(t, err, nil, "Has error.")
	assert.Equal(t, i, int32(-1), "int32 error.")
}

func TestShiftUint64(t *testing.T) {
	buf := new(bytes.Buffer)
	p := NewPacker(binary.BigEndian, buf)
	u := NewUnpacker(binary.BigEndian, buf)
	p.PushUint64(1)
	i, err := u.ShiftUint64()
	assert.Equal(t, err, nil, "Has error.")
	assert.Equal(t, i, uint64(1), "uint64 error.")
}

func TestShiftFloat32(t *testing.T) {
	buf := new(bytes.Buffer)
	p := NewPacker(binary.BigEndian, buf)
	u := NewUnpacker(binary.BigEndian, buf)
	p.PushFloat32(math.SmallestNonzeroFloat32)
	i, err := u.ShiftFloat32()
	assert.Equal(t, err, nil, "Has error.")
	// without explicit float32() conversion
	// reflect convert math.SmallestNonzeroFloat32 to float64
	// what is 0.0000000000000000000000000000000000000000000014012984643248170709237295832899161312802619418765157718
	// instead 0.000000000000000000000000000000000000000000001
	assert.Equal(t, i, float32(math.SmallestNonzeroFloat32), "float32 error.")
}

func TestShiftFloat64(t *testing.T) {
	buf := new(bytes.Buffer)
	p := NewPacker(binary.BigEndian, buf)
	u := NewUnpacker(binary.BigEndian, buf)
	p.PushFloat64(math.SmallestNonzeroFloat64)
	i, err := u.ShiftFloat64()
	assert.Equal(t, err, nil, "Has error.")
	assert.Equal(t, i, math.SmallestNonzeroFloat64, "float64 error.")
}

func TestFetchFloat32(t *testing.T) {
	buf := new(bytes.Buffer)
	p := NewPacker(binary.BigEndian, buf)
	u := NewUnpacker(binary.BigEndian, buf)
	p.PushFloat32(math.SmallestNonzeroFloat32)
	var f float32
	u.FetchFloat32(&f)
	assert.Equal(t, f, float32(math.SmallestNonzeroFloat32), "float32 error.")
}

func TestFetchFloat64(t *testing.T) {
	buf := new(bytes.Buffer)
	p := NewPacker(binary.BigEndian, buf)
	u := NewUnpacker(binary.BigEndian, buf)
	p.PushFloat64(math.SmallestNonzeroFloat64)
	var f float64
	u.FetchFloat64(&f)
	assert.Equal(t, f, math.SmallestNonzeroFloat64, "float64 error.")
}

func TestShiftInt64(t *testing.T) {
	buf := new(bytes.Buffer)
	p := NewPacker(binary.BigEndian, buf)
	u := NewUnpacker(binary.BigEndian, buf)
	p.PushInt64(-1)
	i, err := u.ShiftInt64()
	assert.Equal(t, err, nil, "Has error.")
	assert.Equal(t, i, int64(-1), "int64 error.")
}

func TestShiftString(t *testing.T) {
	buf := new(bytes.Buffer)
	p := NewPacker(binary.BigEndian, buf)
	u := NewUnpacker(binary.BigEndian, buf)
	p.PushString("Hi")
	s, err := u.ShiftString(2)
	assert.Equal(t, err, nil, "Has error.")
	assert.Equal(t, s, "Hi", "string error.")
}

func TestRead(t *testing.T) {
	buf := new(bytes.Buffer)
	p := NewPacker(binary.BigEndian, buf)
	u := NewUnpacker(binary.BigEndian, buf)
	p.PushByte(0x01)
	p.PushBytes([]byte("Hi"))
	p.PushUint8(1)
	p.PushUint16(1)
	p.PushInt16(-1)
	p.PushUint32(1)
	p.PushInt32(-1)
	p.PushUint64(1)
	p.PushInt64(-1)
	p.PushString("Hi")
	var b byte
	var bs []byte
	var ui8 uint8
	var ui16 uint16
	var i16 int16
	var ui32 uint32
	var i32 int32
	var ui64 uint64
	var i64 int64
	var s string
	u.FetchByte(&b).
		FetchBytes(2, &bs).
		FetchUint8(&ui8).
		FetchUint16(&ui16).
		FetchInt16(&i16).
		FetchUint32(&ui32).
		FetchInt32(&i32).
		FetchUint64(&ui64).
		FetchInt64(&i64).
		FetchString(2, &s)
	assert.Equal(t, u.err, nil, "Has Error.")
	assert.Equal(t, u.Error(), nil, "Has Error.")
	assert.Equal(t, b, byte(0x01), "byte error.")
	assert.Equal(t, bs, []byte("Hi"), "bytes error.")
	assert.Equal(t, ui8, uint8(1), "uint8 error.")
	assert.Equal(t, ui16, uint16(1), "uint16 error.")
	assert.Equal(t, i16, int16(-1), "int16 error.")
	assert.Equal(t, ui32, uint32(1), "uint32 error.")
	assert.Equal(t, i32, int32(-1), "int32 error.")
	assert.Equal(t, ui64, uint64(1), "uint64 error.")
	assert.Equal(t, i64, int64(-1), "int64 error.")
	assert.Equal(t, s, "Hi", "string error.")
}

func TestReadWithPerfix(t *testing.T) {
	buf := new(bytes.Buffer)
	p := NewPacker(binary.BigEndian, buf)
	u := NewUnpacker(binary.BigEndian, buf)
	var bs []byte
	var s string

	p.PushUint16(2)
	p.PushBytes([]byte("Hi"))
	u.BytesWithUint16Perfix(&bs)
	assert.Equal(t, bs, []byte("Hi"), "Bytes with prefixes error.")
	p.PushUint16(2)
	p.PushString("Hi")
	u.StringWithUint16Perfix(&s)
	assert.Equal(t, s, "Hi", "String with prefixes error.")

	p.PushUint32(2)
	p.PushBytes([]byte("Hi"))
	u.BytesWithUint32Perfix(&bs)
	assert.Equal(t, bs, []byte("Hi"), "Bytes with prefixes error.")
	p.PushUint32(2)
	p.PushString("Hi")
	u.StringWithUint32Perfix(&s)
	assert.Equal(t, s, "Hi", "String with prefixes error.")

	p.PushUint64(2)
	p.PushBytes([]byte("Hi"))
	u.BytesWithUint64Perfix(&bs)
	assert.Equal(t, bs, []byte("Hi"), "Bytes with prefixes error.")
	p.PushUint64(2)
	p.PushString("Hi")
	u.StringWithUint64Perfix(&s)
	assert.Equal(t, s, "Hi", "String with prefixes error.")
}
