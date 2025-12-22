package gssapi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestChannelBindings_Marshal_Empty(t *testing.T) {
	cb := &ChannelBindings{}
	b := cb.Marshal()

	// Should be 20 bytes: 5 x 4-byte fields (all zeros for lengths/types)
	// InitiatorAddrType(4) + InitiatorAddrLen(4) + AcceptorAddrType(4) + AcceptorAddrLen(4) + AppDataLen(4) = 20
	if len(b) != 20 {
		t.Errorf("expected 20 bytes for empty bindings, got %d", len(b))
	}

	// All bytes should be zero for empty bindings
	for i, v := range b {
		if v != 0 {
			t.Errorf("expected byte %d to be 0, got %d", i, v)
		}
	}
}

func TestChannelBindings_Marshal_WithApplicationData(t *testing.T) {
	appData := []byte("tls-server-end-point:test-certificate-hash")
	cb := &ChannelBindings{
		ApplicationData: appData,
	}
	b := cb.Marshal()

	// Size: 20 (base) + len(appData)
	expectedLen := 20 + len(appData)
	if len(b) != expectedLen {
		t.Errorf("expected %d bytes, got %d", expectedLen, len(b))
	}

	// Verify ApplicationData length field is correct
	appDataLenOffset := 16 // After InitiatorAddrType(4) + InitiatorAddrLen(4) + AcceptorAddrType(4) + AcceptorAddrLen(4)
	appDataLen := binary.LittleEndian.Uint32(b[appDataLenOffset : appDataLenOffset+4])
	if appDataLen != uint32(len(appData)) {
		t.Errorf("expected application data length %d, got %d", len(appData), appDataLen)
	}

	// Verify ApplicationData content
	if !bytes.Equal(b[appDataLenOffset+4:], appData) {
		t.Error("application data content mismatch")
	}
}

func TestChannelBindings_Marshal_WithAllFields(t *testing.T) {
	cb := &ChannelBindings{
		InitiatorAddrType: AddressTypeIPv4,
		InitiatorAddress:  []byte{192, 168, 1, 100},
		AcceptorAddrType:  AddressTypeIPv4,
		AcceptorAddress:   []byte{10, 0, 0, 1},
		ApplicationData:   []byte("tls-server-end-point:hash"),
	}
	b := cb.Marshal()

	// Size: 20 (base) + 4 (initiator addr) + 4 (acceptor addr) + 25 (app data)
	expectedLen := 20 + len(cb.InitiatorAddress) + len(cb.AcceptorAddress) + len(cb.ApplicationData)
	if len(b) != expectedLen {
		t.Errorf("expected %d bytes, got %d", expectedLen, len(b))
	}

	offset := 0

	// Verify InitiatorAddrType
	initiatorAddrType := binary.LittleEndian.Uint32(b[offset : offset+4])
	if initiatorAddrType != AddressTypeIPv4 {
		t.Errorf("expected initiator addr type %d, got %d", AddressTypeIPv4, initiatorAddrType)
	}
	offset += 4

	// Verify InitiatorAddress length
	initiatorAddrLen := binary.LittleEndian.Uint32(b[offset : offset+4])
	if initiatorAddrLen != 4 {
		t.Errorf("expected initiator addr length 4, got %d", initiatorAddrLen)
	}
	offset += 4

	// Verify InitiatorAddress
	if !bytes.Equal(b[offset:offset+4], cb.InitiatorAddress) {
		t.Error("initiator address mismatch")
	}
	offset += 4

	// Verify AcceptorAddrType
	acceptorAddrType := binary.LittleEndian.Uint32(b[offset : offset+4])
	if acceptorAddrType != AddressTypeIPv4 {
		t.Errorf("expected acceptor addr type %d, got %d", AddressTypeIPv4, acceptorAddrType)
	}
	offset += 4

	// Verify AcceptorAddress length
	acceptorAddrLen := binary.LittleEndian.Uint32(b[offset : offset+4])
	if acceptorAddrLen != 4 {
		t.Errorf("expected acceptor addr length 4, got %d", acceptorAddrLen)
	}
	offset += 4

	// Verify AcceptorAddress
	if !bytes.Equal(b[offset:offset+4], cb.AcceptorAddress) {
		t.Error("acceptor address mismatch")
	}
}

func TestChannelBindings_Marshal_Deterministic(t *testing.T) {
	cb := &ChannelBindings{
		InitiatorAddrType: AddressTypeIPv4,
		InitiatorAddress:  []byte{192, 168, 1, 1},
		AcceptorAddrType:  AddressTypeIPv4,
		AcceptorAddress:   []byte{10, 0, 0, 1},
		ApplicationData:   []byte("tls-server-end-point:test"),
	}

	// Multiple calls should produce identical output
	b1 := cb.Marshal()
	b2 := cb.Marshal()

	if !bytes.Equal(b1, b2) {
		t.Error("Marshal should be deterministic")
	}
}

func TestChannelBindings_MD5Hash(t *testing.T) {
	cb := &ChannelBindings{
		ApplicationData: []byte("test-application-data"),
	}
	hash := cb.MD5Hash()

	// Verify hash is 16 bytes (MD5 produces 128-bit hash)
	if len(hash) != 16 {
		t.Errorf("expected 16 byte hash, got %d", len(hash))
	}

	// Verify hash is non-zero
	allZero := true
	for _, b := range hash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("hash should not be all zeros")
	}
}

func TestChannelBindings_MD5Hash_Deterministic(t *testing.T) {
	cb := &ChannelBindings{
		InitiatorAddrType: AddressTypeIPv4,
		InitiatorAddress:  []byte{192, 168, 1, 1},
		AcceptorAddrType:  AddressTypeIPv4,
		AcceptorAddress:   []byte{10, 0, 0, 1},
		ApplicationData:   []byte("tls-server-end-point:test"),
	}

	h1 := cb.MD5Hash()
	h2 := cb.MD5Hash()

	if h1 != h2 {
		t.Error("MD5Hash should be deterministic")
	}
}

func TestChannelBindings_MD5Hash_DifferentInputs(t *testing.T) {
	cb1 := &ChannelBindings{
		ApplicationData: []byte("data1"),
	}
	cb2 := &ChannelBindings{
		ApplicationData: []byte("data2"),
	}

	h1 := cb1.MD5Hash()
	h2 := cb2.MD5Hash()

	if h1 == h2 {
		t.Error("different inputs should produce different hashes")
	}
}

func TestChannelBindings_MD5Hash_Empty(t *testing.T) {
	cb := &ChannelBindings{}
	hash := cb.MD5Hash()

	// Empty bindings should still produce a valid hash (of the 20-byte zero serialization)
	if len(hash) != 16 {
		t.Errorf("expected 16 byte hash, got %d", len(hash))
	}

	// The hash of 20 zero bytes is well-defined, verify it's consistent
	hash2 := cb.MD5Hash()
	if hash != hash2 {
		t.Error("empty bindings hash should be consistent")
	}
}
