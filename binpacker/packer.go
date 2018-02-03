package binpacker

import (
	"encoding/binary"
	"io"
	"math"
)

// Packer is a binary packer helps you pack data into an io.Writer.
type Packer struct {
	writer io.Writer
	endian binary.ByteOrder
	err    error
}

// NewPacker returns a *Packer hold an io.Writer. User must provide the byte order explicitly.
func NewPacker(endian binary.ByteOrder, writer io.Writer) *Packer {
	return &Packer{
		writer: writer,
		endian: endian,
	}
}

// Error returns an error if any errors exists
func (p *Packer) Error() error {
	return p.err
}

// PushByte write a single byte into writer.
func (p *Packer) PushByte(b byte) *Packer {
	return p.errFilter(func() {
		_, p.err = p.writer.Write([]byte{b})
	})
}

// PushBytes write a bytes array into writer.
func (p *Packer) PushBytes(bytes []byte) *Packer {
	return p.errFilter(func() {
		_, p.err = p.writer.Write(bytes)
	})
}

// PushUint8 write a uint8 into writer.
func (p *Packer) PushUint8(i uint8) *Packer {
	return p.errFilter(func() {
		_, p.err = p.writer.Write([]byte{byte(i)})
	})
}

// PushUint16 write a uint16 into writer.
func (p *Packer) PushUint16(i uint16) *Packer {
	return p.errFilter(func() {
		buffer := make([]byte, 2)
		p.endian.PutUint16(buffer, i)
		_, p.err = p.writer.Write(buffer)
	})
}

// PushUint16 write a int16 into writer.
func (p *Packer) PushInt16(i int16) *Packer {
	return p.PushUint16(uint16(i))
}

// PushUint32 write a uint32 into writer.
func (p *Packer) PushUint32(i uint32) *Packer {
	return p.errFilter(func() {
		buffer := make([]byte, 4)
		p.endian.PutUint32(buffer, i)
		_, p.err = p.writer.Write(buffer)
	})
}

// PushInt32 write a int32 into writer.
func (p *Packer) PushInt32(i int32) *Packer {
	return p.PushUint32(uint32(i))
}

// PushUint64 write a uint64 into writer.
func (p *Packer) PushUint64(i uint64) *Packer {
	return p.errFilter(func() {
		buffer := make([]byte, 8)
		p.endian.PutUint64(buffer, i)
		_, p.err = p.writer.Write(buffer)
	})
}

// PushInt64 write a int64 into writer.
func (p *Packer) PushInt64(i int64) *Packer {
	return p.PushUint64(uint64(i))
}

// PushFloat32 write a float32 into writer.
func (p *Packer) PushFloat32(i float32) *Packer {
	return p.PushUint32(math.Float32bits(i))
}

// PushFloat64 write a float64 into writer.
func (p *Packer) PushFloat64(i float64) *Packer {
	return p.PushUint64(math.Float64bits(i))
}

// PushString write a string into writer.
func (p *Packer) PushString(s string) *Packer {
	return p.errFilter(func() {
		_, p.err = p.writer.Write([]byte(s))
	})
}

func (p *Packer) errFilter(f func()) *Packer {
	if p.err == nil {
		f()
	}
	return p
}
