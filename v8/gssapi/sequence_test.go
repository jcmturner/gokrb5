package gssapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func makeRange(min, max uint64) []uint64 {
	a := make([]uint64, max-min+1)
	for i := range a {
		a[i] = min + uint64(i)
	}
	return a
}

func TestSequenceState(t *testing.T) {
	tables := map[string]struct {
		base       uint64
		doReplay   bool
		doSequence bool
		wide       bool
		sequence   []uint64
		err        error
	}{
		"noop": {
			0,
			false,
			false,
			false,
			makeRange(0, 64),
			nil,
		},
		"ok": {
			0,
			true,
			true,
			true,
			makeRange(0, 64),
			nil,
		},
		"replay skip": {
			0,
			true,
			false,
			true,
			append(makeRange(0, 64), 66),
			nil,
		},
		"sequence skip": {
			0,
			false,
			true,
			true,
			append(makeRange(0, 64), 66),
			errGapToken,
		},
		"replay too old": {
			0,
			true,
			false,
			true,
			append(makeRange(0, 64), 0),
			errOldToken,
		},
		"sequence too old": {
			0,
			false,
			true,
			true,
			append(makeRange(0, 64), 0),
			errUnseqToken,
		},
		"replay duplicate": {
			0,
			true,
			false,
			true,
			append(makeRange(0, 64), 64),
			errDuplicateToken,
		},
		"sequence duplicate": {
			0,
			false,
			true,
			true,
			append(makeRange(0, 64), 64),
			errUnseqToken,
		},
		"replay out of order": {
			0,
			true,
			false,
			true,
			append(makeRange(0, 64), 66, 65),
			nil,
		},
	}

	for name, table := range tables {
		t.Run(name, func(t *testing.T) {
			ss := NewSequenceState(table.base, table.doReplay, table.doSequence, table.wide)

			var err error
			for _, next := range table.sequence {
				err = ss.Check(next)
				if err != nil {
					break
				}
			}

			assert.Equal(t, table.err, err)
		})
	}
}
