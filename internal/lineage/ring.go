package lineage

import "sync/atomic"

// Ring is a bounded lock-free queue for many producers and ONE consumer
// (Vyukov's bounded queue; the consumer side is not safe for concurrent use).
// Push never blocks: when the ring is full it returns false and the caller
// drops and counts the event (lineage is observability, not a transaction log).
type Ring struct {
	mask  uint64
	slots []slot
	_     [56]byte
	head  atomic.Uint64 // next enqueue position
	_     [56]byte
	tail  atomic.Uint64 // next dequeue position (written only by the consumer; read by Len)
}

type slot struct {
	seq atomic.Uint64
	ev  *Event
}

// NewRing returns a ring with size slots (rounded up to a power of two, >= 2).
func NewRing(size int) *Ring {
	n := 2
	for n < size {
		n <<= 1
	}
	r := &Ring{mask: uint64(n - 1), slots: make([]slot, n)}
	for i := range r.slots {
		r.slots[i].seq.Store(uint64(i))
	}
	return r
}

// Cap is the number of slots.
func (r *Ring) Cap() int { return len(r.slots) }

// Push enqueues e; false means the ring is full.
func (r *Ring) Push(e *Event) bool {
	for {
		pos := r.head.Load()
		s := &r.slots[pos&r.mask]
		dif := int64(s.seq.Load()) - int64(pos)
		switch {
		case dif == 0:
			if r.head.CompareAndSwap(pos, pos+1) {
				s.ev = e
				s.seq.Store(pos + 1) // publish
				return true
			}
		case dif < 0:
			return false
		}
		// another producer claimed this position: reload and retry
	}
}

// Pop dequeues one event (single consumer).
func (r *Ring) Pop() (*Event, bool) {
	tail := r.tail.Load()
	s := &r.slots[tail&r.mask]
	if int64(s.seq.Load())-int64(tail+1) != 0 {
		return nil, false
	}
	e := s.ev
	s.ev = nil
	s.seq.Store(tail + r.mask + 1) // free the slot for the producer one lap ahead
	r.tail.Store(tail + 1)
	return e, true
}

// Len is an approximate number of queued events.
func (r *Ring) Len() int {
	h, t := r.head.Load(), r.tail.Load()
	if h < t {
		return 0
	}
	return int(h - t)
}
