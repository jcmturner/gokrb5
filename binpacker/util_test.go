package binpacker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddUint16Perfix(t *testing.T) {
	bytes := []byte{1}
	assert.Equal(t, AddUint16Perfix(bytes), []byte{1, 0, 1}, "Perfix error.")
}

func TestAddUint32Perfix(t *testing.T) {
	bytes := []byte{1}
	assert.Equal(t, AddUint32Perfix(bytes), []byte{1, 0, 0, 0, 1}, "Perfix error.")
}

func TestAddUint64Perfix(t *testing.T) {
	bytes := []byte{1}
	assert.Equal(t, AddUint64Perfix(bytes), []byte{1, 0, 0, 0, 0, 0, 0, 0, 1}, "Perfix error.")
}
