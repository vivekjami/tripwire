package lineage

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Sink persists batches. Implementations must not retain the slice or events
// after returning.
type Sink interface {
	WriteBatch(ctx context.Context, batch []*Event) error
	Close() error
}

// Config tunes the pipeline.
type Config struct {
	RingSize   int           // slots (default 1<<16)
	BatchRows  int           // flush at this many rows (default 50_000)
	FlushEvery time.Duration // or after this long (default 750ms)
	Writers    int           // concurrent sink writers (default 2)
	Retries    int           // sink retries before a batch is dropped (default 3)
	Registry   prometheus.Registerer
}

func (c *Config) defaults() {
	if c.RingSize == 0 {
		c.RingSize = 1 << 16
	}
	if c.BatchRows == 0 {
		c.BatchRows = 50_000
	}
	if c.FlushEvery == 0 {
		c.FlushEvery = 750 * time.Millisecond
	}
	if c.Writers == 0 {
		c.Writers = 2
	}
	if c.Retries == 0 {
		c.Retries = 3
	}
}

// Stats are cumulative counters.
type Stats struct {
	Emitted   uint64 // accepted into the ring
	Dropped   uint64 // ring full
	Committed uint64 // acknowledged by the sink
	Failed    uint64 // lost after sink retries (no WAL spill yet: Phase 4)
	Batches   uint64
}

// Pipeline is Emit -> ring -> batcher -> writers -> Sink.
type Pipeline struct {
	cfg  Config
	ring *Ring
	sink Sink

	emitted, dropped, committed, failed, batches atomic.Uint64

	batchc chan []*Event
	stop   chan struct{}
	wg     sync.WaitGroup
	closed atomic.Bool

	mEmitted, mDropped, mCommitted, mFailed prometheus.Counter
	mDepth                                  prometheus.GaugeFunc
	mBatch                                  prometheus.Histogram
}

// New starts a pipeline writing to sink.
func New(cfg Config, sink Sink) *Pipeline {
	cfg.defaults()
	p := &Pipeline{cfg: cfg, ring: NewRing(cfg.RingSize), sink: sink,
		batchc: make(chan []*Event, cfg.Writers*2), stop: make(chan struct{})}
	p.mEmitted = prometheus.NewCounter(prometheus.CounterOpts{Name: "tw_lineage_events_total", Help: "Lineage events accepted into the ring."})
	p.mDropped = prometheus.NewCounter(prometheus.CounterOpts{Name: "tw_lineage_dropped_total", Help: "Lineage events dropped because the ring was full."})
	p.mCommitted = prometheus.NewCounter(prometheus.CounterOpts{Name: "tw_lineage_committed_total", Help: "Lineage events acknowledged by the sink."})
	p.mFailed = prometheus.NewCounter(prometheus.CounterOpts{Name: "tw_lineage_failed_total", Help: "Lineage events lost after sink retries."})
	p.mDepth = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "tw_lineage_queue_depth", Help: "Events waiting in the ring."}, func() float64 { return float64(p.ring.Len()) })
	p.mBatch = prometheus.NewHistogram(prometheus.HistogramOpts{Name: "tw_lineage_batch_rows", Help: "Rows per sink batch.", Buckets: prometheus.ExponentialBuckets(1, 4, 12)})
	if cfg.Registry != nil {
		cfg.Registry.MustRegister(p.mEmitted, p.mDropped, p.mCommitted, p.mFailed, p.mDepth, p.mBatch)
	}
	for i := 0; i < cfg.Writers; i++ {
		p.wg.Add(1)
		go p.writer()
	}
	p.wg.Add(1)
	go p.batcher()
	return p
}

// Emit hands an event to the pipeline. It never blocks and never fails the
// caller: a full ring drops the event (counted). Ownership of e transfers.
func (p *Pipeline) Emit(e *Event) bool {
	if p == nil {
		release(e)
		return false
	}
	if p.closed.Load() || !p.ring.Push(e) {
		p.dropped.Add(1)
		p.mDropped.Inc()
		release(e)
		return false
	}
	p.emitted.Add(1)
	p.mEmitted.Inc()
	return true
}

// Stats returns a snapshot.
func (p *Pipeline) Stats() Stats {
	return Stats{p.emitted.Load(), p.dropped.Load(), p.committed.Load(), p.failed.Load(), p.batches.Load()}
}

func (p *Pipeline) batcher() {
	defer p.wg.Done()
	defer close(p.batchc)
	t := time.NewTicker(p.cfg.FlushEvery / 4)
	defer t.Stop()
	batch := make([]*Event, 0, p.cfg.BatchRows)
	last := time.Now()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		p.batchc <- batch
		batch = make([]*Event, 0, p.cfg.BatchRows)
		last = time.Now()
	}
	drain := func() {
		for len(batch) < p.cfg.BatchRows {
			e, ok := p.ring.Pop()
			if !ok {
				return
			}
			batch = append(batch, e)
		}
	}
	for {
		drain()
		if len(batch) >= p.cfg.BatchRows {
			flush()
			continue
		}
		select {
		case <-p.stop:
			for { // final drain
				drain()
				if len(batch) == 0 {
					return
				}
				flush()
			}
		case <-t.C:
			if time.Since(last) >= p.cfg.FlushEvery {
				drain()
				flush()
			}
		default:
			time.Sleep(200 * time.Microsecond) // the ring is empty: do not spin
		}
	}
}

func (p *Pipeline) writer() {
	defer p.wg.Done()
	for batch := range p.batchc {
		n := uint64(len(batch))
		var err error
		for attempt := 0; attempt <= p.cfg.Retries; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err = p.sink.WriteBatch(ctx, batch)
			cancel()
			if err == nil {
				break
			}
			time.Sleep(time.Duration(attempt+1) * 50 * time.Millisecond)
		}
		p.batches.Add(1)
		p.mBatch.Observe(float64(n))
		if err == nil {
			p.committed.Add(n)
			p.mCommitted.Add(float64(n))
		} else {
			p.failed.Add(n)
			p.mFailed.Add(float64(n))
		}
		for _, e := range batch {
			release(e)
		}
	}
}

// Close stops accepting events, flushes everything queued, and closes the sink.
func (p *Pipeline) Close() error {
	if p == nil || !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(p.stop)
	p.wg.Wait()
	return p.sink.Close()
}

// ErrNoSink is returned by constructors that need a sink.
var ErrNoSink = errors.New("lineage: no sink")

// ---- sinks -----------------------------------------------------------------------

// NullSink discards batches (counting them): the Phase 1 default.
type NullSink struct{ Rows atomic.Uint64 }

// WriteBatch implements Sink.
func (s *NullSink) WriteBatch(_ context.Context, b []*Event) error {
	s.Rows.Add(uint64(len(b)))
	return nil
}

// Close implements Sink.
func (s *NullSink) Close() error { return nil }

// MemorySink keeps copies of request events for tests.
type MemorySink struct {
	mu   sync.Mutex
	Reqs []Event
	Fail atomic.Int64 // number of upcoming WriteBatch calls to fail
}

// WriteBatch implements Sink.
func (s *MemorySink) WriteBatch(_ context.Context, b []*Event) error {
	if s.Fail.Add(-1) >= 0 {
		return errors.New("memory sink: injected failure")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range b {
		s.Reqs = append(s.Reqs, *e)
	}
	return nil
}

// Close implements Sink.
func (s *MemorySink) Close() error { return nil }

// Snapshot returns a copy of the stored events.
func (s *MemorySink) Snapshot() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.Reqs...)
}
