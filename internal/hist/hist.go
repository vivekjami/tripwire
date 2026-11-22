// Package hist wraps HdrHistogram for concurrent recording. Recording is
// sharded so thousands of goroutines can record without serialising on one
// mutex; percentiles are only ever computed on the MERGED histogram (never
// average percentiles; IMPLEMENTATION_PLAN §12.3).
package hist

import (
	"fmt"
	"math/bits"
	"os"
	"sync"
	"sync/atomic"

	hdr "github.com/HdrHistogram/hdrhistogram-go"
)

const shardCount = 64

type shard struct {
	mu sync.Mutex
	h  *hdr.Histogram
	_  [40]byte // keep shards on separate cache lines
}

// Sharded is a concurrency-safe recorder.
type Sharded struct {
	shards [shardCount]shard
	next   atomic.Uint64
	max    int64
	sig    int
}

// New returns a recorder for values in [1, max] with sig significant digits.
// Values are recorded in microseconds across Tripwire's tooling (1 µs
// resolution, as specified in IMPLEMENTATION_PLAN WP0.3).
func New(max int64, sig int) *Sharded {
	s := &Sharded{max: max, sig: sig}
	for i := range s.shards {
		s.shards[i].h = hdr.New(1, max, sig)
	}
	return s
}

// Record records one value (clamped into range, so an outlier is never lost).
func (s *Sharded) Record(v int64) {
	if v < 1 {
		v = 1
	}
	if v > s.max {
		v = s.max
	}
	sh := &s.shards[(s.next.Add(1)*0x9e3779b97f4a7c15)>>(64-bits.Len(shardCount-1))%shardCount]
	sh.mu.Lock()
	_ = sh.h.RecordValue(v)
	sh.mu.Unlock()
}

// Merge returns a fresh histogram combining all shards.
func (s *Sharded) Merge() *hdr.Histogram {
	out := hdr.New(1, s.max, s.sig)
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		out.Merge(sh.h)
		sh.mu.Unlock()
	}
	return out
}

// Percentiles is the standard summary we publish.
type Percentiles struct {
	Count int64   `json:"count"`
	Min   int64   `json:"min_us"`
	P50   int64   `json:"p50_us"`
	P90   int64   `json:"p90_us"`
	P99   int64   `json:"p99_us"`
	P999  int64   `json:"p999_us"`
	Max   int64   `json:"max_us"`
	Mean  float64 `json:"mean_us"`
}

// Summarize extracts the standard percentiles from a histogram.
func Summarize(h *hdr.Histogram) Percentiles {
	if h.TotalCount() == 0 {
		return Percentiles{}
	}
	return Percentiles{
		Count: h.TotalCount(),
		Min:   h.Min(),
		P50:   h.ValueAtPercentile(50),
		P90:   h.ValueAtPercentile(90),
		P99:   h.ValueAtPercentile(99),
		P999:  h.ValueAtPercentile(99.9),
		Max:   h.Max(),
		Mean:  h.Mean(),
	}
}

// Save writes the histogram in HdrHistogram's compressed V2 encoding.
func Save(path string, h *hdr.Histogram) error {
	b, err := h.Encode(hdr.V2CompressedEncodingCookieBase)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Load reads a histogram written by Save.
func Load(path string) (*hdr.Histogram, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("hist: %w", err)
	}
	return hdr.Decode(b)
}
