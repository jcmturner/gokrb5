# binpacker [![Build Status](https://travis-ci.org/zhuangsirui/binpacker.svg?branch=master)](https://travis-ci.org/zhuangsirui/binpacker) [![GoDoc](https://godoc.org/github.com/zhuangsirui/binpacker?status.svg)](https://godoc.org/github.com/zhuangsirui/binpacker) [![Go Report Card](https://goreportcard.com/badge/github.com/zhuangsirui/binpacker)](https://goreportcard.com/report/github.com/zhuangsirui/binpacker)
A binary packer and unpacker.

# Install

```bash
go get github.com/zhuangsirui/binpacker
```

# Examples

## Packer

```go
buffer := new(bytes.Buffer)
packer := binpacker.NewPacker(binary.BigEndian, buffer)
packer.PushByte(0x01)
packer.PushBytes([]byte{0x02, 0x03})
packer.PushUint16(math.MaxUint16)
```

```go
// You can push data like this
buffer := new(bytes.Buffer)
packer := binpacker.NewPacker(binary.BigEndian, buffer)
packer.PushByte(0x01).PushBytes([]byte{0x02, 0x03}).PushUint16(math.MaxUint16)
packer.Error() // Make sure error is nil
```

## Unpacker

**Example data**

```go
buffer := new(bytes.Buffer)
packer := binpacker.NewPacker(binary.BigEndian, buffer)
unpacker := binpacker.NewUnpacker(binary.BigEndian, buffer)
packer.PushByte(0x01)
packer.PushUint16(math.MaxUint16)
```

```go
var val1 byte
var val2 uint16
var err error
val1, err = unpacker.ShiftByte()
val2, err = unpacker.ShiftUint16()
```

```go
var val1 byte
var val2 uint16
var err error
unpacker.FetchByte(&val1).FetchUint16(&val2)
unpacker.Error() // Make sure error is nil
```
