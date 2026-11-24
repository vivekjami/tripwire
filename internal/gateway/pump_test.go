//go:build !race

package gateway

import (
	"context"
	"io"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vivekjami/tripwire/internal/config"
	"github.com/vivekjami/tripwire/internal/jsonscan"
	"github.com/vivekjami/tripwire/internal/sse"
)

// discardWriter is an allocation-free http.ResponseWriter + Flusher + deadline setter.
type discardWriter struct {
	h       http.Header
	bytes   int
	flushes int
}

func (d *discardWriter) Header() http.Header              { return d.h }
func (d *discardWriter) WriteHeader(int)                  {}
func (d *discardWriter) Write(b []byte) (int, error)      { d.bytes += len(b); return len(b), nil }
func (d *discardWriter) Flush()                           { d.flushes++ }
func (d *discardWriter) SetWriteDeadline(time.Time) error { return nil }

// repeater yields `event` n times then the terminal [DONE], reading in `chunk`-byte pieces.
type repeater struct {
	event []byte
	left  int
	buf   []byte
	pos   int
	done  bool
	chunk int
}

func (r *repeater) Read(p []byte) (int, error) {
	if r.pos >= len(r.buf) {
		r.buf, r.pos = r.buf[:0], 0
		for len(r.buf) < r.chunk && r.left > 0 {
			r.buf = append(r.buf, r.event...)
			r.left--
		}
		if r.left == 0 && !r.done {
			r.buf = append(r.buf, "data: [DONE]\n\n"...)
			r.done = true
		}
		if len(r.buf) == 0 {
			return 0, io.EOF
		}
	}
	n := copy(p, r.buf[r.pos:])
	r.pos += n
	return n, nil
}

// The gateway's own per-event path (decode, strict scan, forward, flush, metrics,
// timing) must not allocate. The loop is driven with an in-memory writer, so the
// numbers are the gateway's alone (net/http's chunk writer allocates a boxed length per
// flush of 256+ bytes; that is the standard library's, and is excluded here by design).
func TestPumpPerEventPathDoesNotAllocate(t *testing.T) {
	cfg := config.Defaults()
	s := &Server{cfg: &cfg, opt: Options{Metrics: prometheus.NewRegistry()}}
	a := &chatAPI{s: s, swalker: noopStreamWalker{}}
	a.sm = newStreamMetrics(a)
	ev := []byte("data: " + chunkJSON(0, "hello world token") + "\n\n")

	measure := func(events, chunk int) uint64 {
		w := &discardWriter{h: http.Header{}}
		dec := sse.NewDecoder(&repeater{event: ev, left: events, chunk: chunk}, 1<<20)
		sc := a.sm.scPool.Get().(*jsonscan.Scanner)
		p := &pump{a: a, m: a.sm, w: w, rc: http.NewResponseController(w), dec: dec, sc: sc, rs: nil, lim: cfg.Limits,
			start: time.Now(), first: true, ctx: context.Background(), reqCtx: context.Background()}
		var m0, m1 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m0)
		p.run()
		runtime.ReadMemStats(&m1)
		if w.bytes < events*len(ev) {
			t.Fatalf("forwarded %d bytes, want >= %d", w.bytes, events*len(ev))
		}
		return m1.Mallocs - m0.Mallocs
	}
	for _, chunk := range []int{len(ev), 8 * len(ev), 4096} { // one event per read, small bursts, large bursts
		small, large := measure(20_000, chunk), measure(120_000, chunk)
		perEvent := float64(int64(large)-int64(small)) / 100_000 // may be slightly negative: GC and pool noise in the setup cost
		t.Logf("read chunk %5dB: %d allocs for 20k events, %d for 120k -> %.4f allocs/event (marginal)", chunk, small, large, perEvent)
		if perEvent > 0.001 {
			t.Fatalf("read chunk %d: the per-event path allocates (%.4f allocs/event)", chunk, perEvent)
		}
	}
}
