package types

import (
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKerbPaPacRequest_Marshal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		includePAC bool
	}{
		{"Request PAC", true},
		{"Suppress PAC", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pacReq := KerbPaPacRequest{
				IncludePAC: tt.includePAC,
			}

			data, err := pacReq.Marshal()
			require.NoError(t, err, "Marshal should not error")
			assert.NotEmpty(t, data, "Marshaled data should not be empty")

			// Verify it can be unmarshaled
			var decoded KerbPaPacRequest
			err = decoded.Unmarshal(data)
			require.NoError(t, err, "Unmarshal should not error")
			assert.Equal(t, tt.includePAC, decoded.IncludePAC, "IncludePAC should match")
		})
	}
}

func TestKerbPaPacRequest_Unmarshal(t *testing.T) {
	t.Parallel()

	// Create a valid KerbPaPacRequest with includePAC = true
	pacReq := KerbPaPacRequest{IncludePAC: true}
	data, err := asn1.Marshal(pacReq)
	require.NoError(t, err)

	var decoded KerbPaPacRequest
	err = decoded.Unmarshal(data)
	require.NoError(t, err, "Unmarshal should not error")
	assert.True(t, decoded.IncludePAC, "IncludePAC should be true")
}
