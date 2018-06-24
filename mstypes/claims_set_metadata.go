package mstypes

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"gopkg.in/jcmturner/gokrb5.v5/ndr"
)

// Compression format assigned numbers.
const (
	CompressionFormatNone       = 0
	CompressionFormatLZNT1      = 2
	CompressionFormatXPress     = 3
	CompressionFormatXPressHuff = 4
)

// Claim Type assigned numbers
const (
	ClaimTypeIDInt64    = 1
	ClaimTypeIDUInt64   = 2
	ClaimTypeIDString   = 3
	ClaimsTypeIDBoolean = 6
)

// ClaimsBlob implements https://msdn.microsoft.com/en-us/library/hh554119.aspx
type ClaimsBlob struct {
	ULBlobSizeinBytes uint32
	EncodedBlob       []byte
}

func ReadClaimsBlob(b *[]byte, p *int, e *binary.ByteOrder) (c ClaimsBlob) {
	c.ULBlobSizeinBytes = ndr.ReadUint32(b, p, e)
	c.EncodedBlob = (*b)[*p:]
	//c.EncodedBlob = ndr.ReadBytes(b, p, int(c.ULBlobSizeinBytes), e)
	return
}

// ClaimsSetMetadata implements https://msdn.microsoft.com/en-us/library/hh554073.aspx
type ClaimsSetMetadata struct {
	ULClaimsSetSize             uint32
	ClaimsSet                   ClaimsSet
	USCompressionFormat         uint16 // Enum see constants for options
	ULUncompressedClaimsSetSize uint32
	USReservedType              uint16
	ULReservedFieldSize         uint32
	ReservedField               []byte
}

type ClaimsSet struct {
	ULClaimsArrayCount  uint32
	claimsArrayPtr      uint32
	ClaimsArrays        []ClaimsArray
	USReservedType      uint16
	ULReservedFieldSize uint32
	ReservedField       []byte
}

type ClaimsArray struct {
	USClaimsSourceType uint16
	ULClaimsCount      uint32
	ClaimsEntries      []ClaimEntry
}

// ReadClaimsSetMetadata reads a ClaimsSetMetadata from the bytes slice.
func ReadClaimsSetMetadata(b *[]byte, p *int, e *binary.ByteOrder) (c ClaimsSetMetadata) {
	fmt.Fprintf(os.Stderr, "metabytes: %v\n", (*b)[*p:]) //TODO remove
	c.ULClaimsSetSize = ndr.ReadUint32(b, p, e)
	ndr.ReadUint32(b, p, e) //ptr //TODO
	c.USCompressionFormat = ndr.ReadUint16(b, p, e)
	c.ULUncompressedClaimsSetSize = ndr.ReadUint32(b, p, e)
	c.USReservedType = ndr.ReadUint16(b, p, e)
	c.ULReservedFieldSize = ndr.ReadUint32(b, p, e)
	ndr.ReadUint32(b, p, e) //ptr
	if c.ULClaimsSetSize > 0 {
		*p += 4 //TODO
		csb := ndr.ReadBytes(b, p, int(c.ULClaimsSetSize), e)
		c.ClaimsSet, _ = ReadClaimsSet(csb) //TODO handle err
	}
	if c.ULReservedFieldSize > 0 {
		c.ReservedField = ndr.ReadBytes(b, p, int(c.ULReservedFieldSize), e)
	}
	return
}

// ReadClaimsSet reads a ClaimsSet from the bytes slice.
func ReadClaimsSet(b []byte) (ClaimsSet, error) {
	var c ClaimsSet
	ch, _, p, err := ndr.ReadHeaders(&b)
	if err != nil {
		return c, fmt.Errorf("error parsing byte stream headers: %v", err)
	}
	e := &ch.Endianness

	//The next 4 bytes are an RPC unique pointer referent. We just skip these
	p += 4

	c.ULClaimsArrayCount = ndr.ReadUint32(&b, &p, e)
	c.claimsArrayPtr = ndr.ReadUint32(&b, &p, e) // claims array pointer
	c.USReservedType = ndr.ReadUint16(&b, &p, e)
	c.ULReservedFieldSize = ndr.ReadUint32(&b, &p, e)
	ndr.ReadUint32(&b, &p, e) //TODO reserved ptr
	if c.ULClaimsArrayCount > 0 {
		ac := ndr.ReadUniDimensionalConformantArrayHeader(&b, &p, e)
		if ac != int(c.ULClaimsArrayCount) {
			return c, errors.New("error with size of claims array")
		}
		c.ClaimsArrays = make([]ClaimsArray, c.ULClaimsArrayCount, c.ULClaimsArrayCount)
		for i := range c.ClaimsArrays {
			c.ClaimsArrays[i] = ReadClaimsArray(&b, &p, e)
		}
	}
	if c.ULReservedFieldSize > 0 {
		c.ReservedField = ndr.ReadBytes(&b, &p, int(c.ULReservedFieldSize), e)
	}
	return c, nil
}

func ReadClaimsArray(b *[]byte, p *int, e *binary.ByteOrder) (c ClaimsArray) {
	//Not sure about the first element
	c.USClaimsSourceType = ndr.ReadUint16(b, p, e)
	c.ULClaimsCount = ndr.ReadUint32(b, p, e)
	ndr.ReadUint32(b, p, e) //TODO ptr
	var i uint32
	for i < c.ULClaimsCount {
		var ce ClaimEntry
		//p 140 sub 88
		ce.ID = ndr.ReadUTF16NullTermString(b, p, e)
		ce.Type = ndr.ReadUint16(b, p, e)
		switch ce.Type {
		case ClaimTypeIDInt64:
			ce.TypeInt64.ValueCount = ndr.ReadUint32(b, p, e)
			ce.TypeInt64.Value, _ = binary.Varint((*b)[*p : *p+8])
			*p += 8
		case ClaimTypeIDUInt64:
			ce.TypeUInt64.ValueCount = ndr.ReadUint32(b, p, e)
			ce.TypeUInt64.Value = ndr.ReadUint64(b, p, e)
		case ClaimTypeIDString:
			ce.TypeString.ValueCount = ndr.ReadUint32(b, p, e)
			// 244
			ce.TypeString.Value = "TODO"
		case ClaimsTypeIDBoolean:
			ce.TypeBool.ValueCount = ndr.ReadUint32(b, p, e)
			if ndr.ReadUint64(b, p, e) != 0 {
				ce.TypeBool.Value = true
			}
		}
		i++
	}
	return
}

//type ClaimsSourceType
//
//	typedef  enum _CLAIMS_SOURCE_TYPE
//{
//CLAIMS_SOURCE_TYPE_AD = 1,
//CLAIMS_SOURCE_TYPE_CERTIFICATE
//} CLAIMS_SOURCE_TYPE;
//
//typedef struct _CLAIMS_ARRAY {
//CLAIMS_SOURCE_TYPE usClaimsSourceType;
//ULONG ulClaimsCount;
//[size_is(ulClaimsCount)] PCLAIM_ENTRY ClaimEntries;
//} CLAIMS_ARRAY,
//*PCLAIMS_ARRAY;

type ClaimEntry struct {
	ID         string //utf16string
	Type       uint16 // enums are 16 bit https://msdn.microsoft.com/en-us/library/windows/desktop/aa366818(v=vs.85).aspx
	TypeInt64  ClaimTypeInt64
	TypeUInt64 ClaimTypeUInt64
	TypeString ClaimTypeString
	TypeBool   ClaimTypeBoolean
}

func ReadClaimEntry(b *[]byte, p *int, e *binary.ByteOrder) (c ClaimEntry) {
	//TODO
	return c
}

type ClaimTypeInt64 struct {
	ValueCount uint32
	Value      int64
}

type ClaimTypeUInt64 struct {
	ValueCount uint32
	Value      uint64
}

type ClaimTypeString struct {
	ValueCount uint32
	Value      string
}

type ClaimTypeBoolean struct {
	ValueCount uint32
	Value      bool
}
