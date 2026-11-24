package gateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vivekjami/tripwire/internal/auth"
	"github.com/vivekjami/tripwire/internal/config"
	"github.com/vivekjami/tripwire/internal/jsonscan"
	"github.com/vivekjami/tripwire/internal/openai"
	"github.com/vivekjami/tripwire/internal/sse"
	"github.com/vivekjami/tripwire/internal/upstream"
)

// StreamWalker is the Phase 2 detector hook for streamed events. Phase 1 uses a
// no-op so that parsing cost is measured in isolation.
type StreamWalker interface {
	Event(doc []byte, locs []jsonscan.Loc) error
}

type noopStreamWalker struct{}

func (noopStreamWalker) Event([]byte, []jsonscan.Loc) error { return nil }

type streamMetrics struct {
	active  prometheus.Gauge
	total   *prometheus.CounterVec
	events  prometheus.Counter
	bytes   prometheus.Counter
	added   prometheus.Histogram
	ttfe    prometheus.Histogram
	decPool sync.Pool
	scPool  sync.Pool
}

func newStreamMetrics(a *chatAPI) *streamMetrics {
	m := &streamMetrics{
		active: prometheus.NewGauge(prometheus.GaugeOpts{Name: "tw_streams_active", Help: "Streaming responses in progress."}),
		total:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tw_streams_total", Help: "Finished streams by result."}, []string{"result"}),
		events: prometheus.NewCounter(prometheus.CounterOpts{Name: "tw_stream_events_total", Help: "SSE events relayed."}),
		bytes:  prometheus.NewCounter(prometheus.CounterOpts{Name: "tw_stream_bytes_total", Help: "SSE bytes relayed to clients."}),
		added: prometheus.NewHistogram(prometheus.HistogramOpts{Name: "tw_stream_event_added_seconds",
			Help:                        "Time the gateway held an event: from fully received to flushed to the client.",
			NativeHistogramBucketFactor: 1.1, NativeHistogramMaxBucketNumber: 100, Buckets: prometheus.ExponentialBuckets(0.00001, 2, 18)}),
		ttfe: prometheus.NewHistogram(prometheus.HistogramOpts{Name: "tw_stream_first_event_seconds",
			Help:                        "Request start to first event flushed to the client.",
			NativeHistogramBucketFactor: 1.1, NativeHistogramMaxBucketNumber: 100, Buckets: prometheus.ExponentialBuckets(0.0005, 2, 16)}),
	}
	for _, v := range []string{"ok", "client_gone", "client_slow_or_gone", "upstream_error", "upstream_status", "bad_event", "event_too_large",
		"too_large", "timeout", "idle", "no_done", "blocked"} {
		m.total.WithLabelValues(v)
	}
	m.decPool.New = func() any { return sse.NewDecoder(nil, a.s.cfg.Limits.EventBytes) }
	lim := jsonscan.DefaultLimits()
	lim.AllowLoneSurrogates = true // a pair may be split across events; the Unescaper rejoins it
	lim.MaxBytes = a.s.cfg.Limits.EventBytes
	m.scPool.New = func() any { var s jsonscan.Scanner; s.Init(lim); return &s }
	a.s.opt.Metrics.MustRegister(m.active, m.total, m.events, m.bytes, m.added, m.ttfe)
	return m
}

// guardedBody enforces the idle gap and the byte cap on an upstream stream.
type guardedBody struct {
	r      io.Reader
	idle   *time.Timer
	every  time.Duration
	budget int64
	over   bool
}

func (g *guardedBody) Read(p []byte) (int, error) {
	n, err := g.r.Read(p)
	if n > 0 {
		g.idle.Reset(g.every)
		g.budget -= int64(n)
		if g.budget < 0 {
			g.over = true
			return n, errStreamTooBig
		}
	}
	return n, err
}

var errStreamTooBig = errors.New("gateway: stream exceeds byte cap")

func (a *chatAPI) stream(w http.ResponseWriter, r *http.Request, ag *auth.Agent, up *upstream.Client, req *openai.Request) {
	m := a.sm
	release, ok := a.s.AcquireStream(ag)
	if !ok {
		w.Header().Set("Retry-After", "1")
		writeErr(w, http.StatusTooManyRequests, "rate_limit_error", "too_many_streams", "too many concurrent streams for this agent")
		return
	}
	defer release()
	m.active.Inc()
	defer m.active.Dec()

	lim := a.s.cfg.Limits
	start := time.Now()
	rs := stateFrom(r.Context())
	ctx, cancel := context.WithTimeout(r.Context(), lim.StreamDuration)
	defer cancel()
	resp, err := up.Do(ctx, upstream.Request{
		Method: http.MethodPost, Path: "/v1/chat/completions", Body: req.Doc, ContentType: "application/json", Stream: true,
		RequestID: RequestIDFrom(r.Context()), Traceparent: r.Header.Get("Traceparent"),
	})
	if err != nil {
		a.upReqs.WithLabelValues(up.Name, "error").Inc()
		m.total.WithLabelValues("upstream_error").Inc()
		upstreamFailure(w, ctx, err)
		return
	}
	defer resp.Body.Close()
	rs.markUpstream() // upstream headers received
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		m.total.WithLabelValues("upstream_status").Inc()
		a.relayBounded(w, ctx, up, resp, start) // an upstream error (or a non-stream answer) is relayed like a non-stream response
		return
	}
	a.upReqs.WithLabelValues(up.Name, "2xx").Inc()

	idle := time.AfterFunc(lim.StreamIdle, cancel)
	defer idle.Stop()
	body := &guardedBody{r: resp.Body, idle: idle, every: lim.StreamIdle, budget: lim.StreamBytes}
	dec := m.decPool.Get().(*sse.Decoder)
	dec.Reset(body)
	defer m.decPool.Put(dec)
	sc := m.scPool.Get().(*jsonscan.Scanner)
	defer m.scPool.Put(sc)

	p := &pump{a: a, m: m, w: w, rc: http.NewResponseController(w), dec: dec, sc: sc, rs: rs, lim: lim, body: body,
		start: start, first: true, ctx: ctx, reqCtx: r.Context()}
	p.run()
}

// pump is the single read-inspect-write loop of one stream (ADR-18). It is a
// type of its own so the per-event path can be measured in isolation (zero
// allocations per event) without a network in the way.
type pump struct {
	a      *chatAPI
	m      *streamMetrics
	w      http.ResponseWriter
	rc     *http.ResponseController
	dec    *sse.Decoder
	sc     *jsonscan.Scanner
	rs     *reqState
	lim    config.Limits
	body   *guardedBody
	start  time.Time
	ctx    context.Context // stream deadline / upstream cancellation
	reqCtx context.Context // the client's request

	wrote    bool
	first    bool
	deadline time.Time // armed write deadline (re-armed when under half remains)

	pendEvents, pendBytes float64
	pendRecv              [64]time.Time // when each written-but-unflushed event was fully received
	nPend                 int
}

func (p *pump) flushCounters() {
	p.m.events.Add(p.pendEvents)
	p.m.bytes.Add(p.pendBytes)
	p.pendEvents, p.pendBytes = 0, 0
}

// write buffers bytes for the client without a syscall; commit flushes them.
// Events already received are written together and flushed ONCE when no further
// complete event is buffered (read coalescing, ARCHITECTURE §12.4): no event
// waits for data that has not arrived, and a burst costs one syscall, not N.
func (p *pump) write(b []byte) error {
	if !p.wrote { // headers go out with the first event, i.e. on the first upstream byte
		setServerTiming(p.w, p.rs)
		h := p.w.Header()
		h.Set("Content-Type", "text/event-stream")
		h.Set("Cache-Control", "no-cache")
		h.Set("X-Accel-Buffering", "no")
		p.w.WriteHeader(http.StatusOK)
		p.wrote = true
	}
	// The write deadline is re-armed only when less than half of it remains: a
	// stalled write is cut off between WriteDeadline/2 and WriteDeadline after it stalls.
	if now := time.Now(); p.deadline.Sub(now) < p.lim.WriteDeadline/2 {
		p.deadline = now.Add(p.lim.WriteDeadline)
		_ = p.rc.SetWriteDeadline(p.deadline) // not supported on every transport: best effort
	}
	_, err := p.w.Write(b)
	return err
}

func (p *pump) commit() error {
	err := p.rc.Flush()
	now := time.Now()
	for i := 0; i < p.nPend; i++ {
		held := now.Sub(p.pendRecv[i])
		p.m.added.Observe(held.Seconds())
		if p.rs != nil {
			p.rs.eventsOut++
			p.rs.addedStream += held.Nanoseconds()
			if us := uint32(held.Microseconds()); us > p.rs.holdMaxUS {
				p.rs.holdMaxUS = us
			}
		}
	}
	if p.nPend > 0 && p.first {
		p.first = false
		p.m.ttfe.Observe(time.Since(p.start).Seconds())
	}
	p.nPend = 0
	return err
}

func (p *pump) flush(b []byte) error { // write + commit, for terminal and error events
	if err := p.write(b); err != nil {
		return err
	}
	return p.commit()
}

func (p *pump) finish(result string) { p.m.total.WithLabelValues(result).Inc() }

func (p *pump) fail(code, msg, result string) {
	p.finish(result)
	if !p.wrote {
		writeErr(p.w, http.StatusBadGateway, "server_error", code, msg)
		return
	}
	// Mid-stream failure protocol (ADR-26): error event, terminal [DONE], close.
	e := `{"error":{"message":` + strconv.Quote(msg) + `,"type":"server_error","code":"` + code + `"}}`
	out := sse.AppendEvent(nil, "", []byte(e))
	out = sse.AppendEvent(out, "", []byte("[DONE]"))
	_ = p.flush(out)
}

func (p *pump) run() {
	defer p.flushCounters()
	for {
		ev, err := p.dec.Next()
		recvd := time.Now()
		if err != nil {
			switch {
			case p.body != nil && p.body.over:
				p.fail("stream_too_large", "stream exceeded the size limit", "too_large")
			case errors.Is(err, sse.ErrEventTooLarge):
				p.fail("event_too_large", "upstream event exceeded the size limit", "event_too_large")
			case p.ctx.Err() != nil && p.reqCtx.Err() != nil:
				p.finish("client_gone")
			case errors.Is(p.ctx.Err(), context.DeadlineExceeded):
				p.fail("stream_timeout", "stream exceeded the time limit", "timeout")
			case p.ctx.Err() != nil:
				p.fail("upstream_stalled", "upstream stopped sending data", "idle")
			case errors.Is(err, io.EOF):
				p.fail("upstream_incomplete", "upstream ended the stream without [DONE]", "no_done")
			default:
				p.fail("upstream_error", "upstream stream failed", "upstream_error")
			}
			return
		}
		if ev.HasData {
			if bytes.Equal(ev.Data, doneMarker) {
				if err := p.flush(ev.Raw); err != nil {
					p.finish("client_gone")
					return
				}
				p.pendEvents++
				p.pendBytes += float64(len(ev.Raw))
				p.finish("ok")
				return
			}
			if _, err := p.sc.Scan(ev.Data); err != nil {
				p.fail("bad_upstream_event", "upstream sent a malformed event", "bad_event")
				return
			}
			if err := p.a.swalker.Event(ev.Data, p.sc.Locs); err != nil {
				p.fail("blocked", "stream blocked by policy", "blocked")
				return
			}
		}
		// Forward the exact bytes received (comments and keep-alives included).
		if err := p.write(ev.Raw); err != nil {
			p.finish("client_slow_or_gone")
			return // the deferred cancel() stops the upstream: no more tokens are paid for
		}
		p.pendRecv[p.nPend] = recvd
		p.nPend++
		p.pendEvents++
		p.pendBytes += float64(len(ev.Raw))
		if p.nPend == len(p.pendRecv) || !p.dec.HasEvent() {
			if err := p.commit(); err != nil {
				p.finish("client_slow_or_gone")
				return
			}
		}
		if p.pendEvents >= 64 {
			p.flushCounters()
		}
	}
}

var doneMarker = []byte("[DONE]")
