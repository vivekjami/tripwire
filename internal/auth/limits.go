package auth

import (
	"sync/atomic"
	"time"
)

// Bucket is a token-bucket rate limiter implemented as GCRA with a single atomic
// (ARCHITECTURE §8.5: "one atomic per bucket"). rps <= 0 means unlimited.
type Bucket struct {
	interval int64 // ns between tokens (T)
	tau      int64 // burst tolerance = T * burst
	tat      atomic.Int64
}

// NewBucket returns a limiter allowing rps sustained with the given burst.
func NewBucket(rps float64, burst int) *Bucket {
	if rps <= 0 {
		return &Bucket{}
	}
	if burst < 1 {
		burst = 1
	}
	t := int64(float64(time.Second) / rps)
	if t < 1 {
		t = 1
	}
	return &Bucket{interval: t, tau: t * int64(burst)}
}

// Allow reports whether a request at now (monotonic ns) is admitted; when it is
// not, retry is how long the caller should wait.
func (b *Bucket) Allow(now int64) (ok bool, retry time.Duration) {
	if b.interval == 0 {
		return true, 0
	}
	for {
		tat := b.tat.Load()
		base := tat
		if now > base {
			base = now
		}
		next := base + b.interval
		if next-now > b.tau+b.interval { // would exceed the burst allowance
			return false, time.Duration(next - now - b.tau - b.interval)
		}
		if b.tat.CompareAndSwap(tat, next) {
			return true, 0
		}
	}
}

// Gate is a counting cap on concurrent holders (streams, in-flight requests).
type Gate struct {
	n   atomic.Int64
	cap int64
}

// NewGate returns a gate admitting at most cap holders (cap <= 0: unlimited).
func NewGate(capacity int64) *Gate { return &Gate{cap: capacity} }

// TryAcquire takes a slot if one is free.
func (g *Gate) TryAcquire() bool {
	if g.cap <= 0 {
		g.n.Add(1)
		return true
	}
	for {
		v := g.n.Load()
		if v >= g.cap {
			return false
		}
		if g.n.CompareAndSwap(v, v+1) {
			return true
		}
	}
}

// Release returns a slot.
func (g *Gate) Release() { g.n.Add(-1) }

// Held is the current number of holders.
func (g *Gate) Held() int64 { return g.n.Load() }
