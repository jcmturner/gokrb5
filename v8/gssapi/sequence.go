package gssapi

import (
	"errors"
	"math"
	"sync"
)

var (
	errDuplicateToken = errors.New("duplicate per-message token detected")
	errOldToken       = errors.New("timed-out per-message token detected")
	errUnseqToken     = errors.New("reordered (early) per-message token detected")
	errGapToken       = errors.New("skipped predecessor token(s) detected")
)

// SequenceState tracks previously seen sequence numbers for message replay
// and/or sequence protection
type SequenceState struct {
	m            sync.Mutex
	doReplay     bool
	doSequence   bool
	base         uint64
	next         uint64
	receiveMask  uint64
	sequenceMask uint64
}

// NewSequenceState returns a new SequenceState seeded with sequenceNumber
// with doReplay and doSequence controlling replay and sequence protection
// respectively and wide controlling whether sequence numbers are expected to
// wrap at a 32- or 64-bit boundary.
func NewSequenceState(sequenceNumber uint64, doReplay, doSequence, wide bool) *SequenceState {
	ss := &SequenceState{
		doReplay:   doReplay,
		doSequence: doSequence,
		base:       sequenceNumber,
	}
	if wide {
		ss.sequenceMask = math.MaxUint64
	} else {
		ss.sequenceMask = math.MaxUint32
	}
	return ss
}

// Check the next sequence number. Sequence protection requires the sequence
// number to increase sequentially with no duplicates or out of order delivery.
// Replay protection relaxes these restrictions to permit limited out of order
// delivery.
func (ss *SequenceState) Check(sequenceNumber uint64) error {
	if !ss.doReplay && !ss.doSequence {
		return nil
	}

	ss.m.Lock()
	defer ss.m.Unlock()

	relativeSequenceNumber := (sequenceNumber - ss.base) & ss.sequenceMask

	if relativeSequenceNumber >= ss.next {
		offset := relativeSequenceNumber - ss.next
		ss.receiveMask = ss.receiveMask<<(offset+1) | 1
		ss.next = (relativeSequenceNumber + 1) & ss.sequenceMask

		if offset > 0 && ss.doSequence {
			return errGapToken
		}

		return nil
	}

	offset := ss.next - relativeSequenceNumber

	if offset > 64 {
		if ss.doSequence {
			return errUnseqToken
		}
		return errOldToken
	}

	bit := uint64(1) << (offset - 1)
	if ss.doReplay && ss.receiveMask&bit != 0 {
		return errDuplicateToken
	}
	ss.receiveMask |= bit
	if ss.doSequence {
		return errUnseqToken
	}

	return nil
}
