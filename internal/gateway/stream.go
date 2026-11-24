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

	rc := http.NewResponseController(w)
	wrote := false
	flush := func(b []byte) error {
		if !wrote { // headers go out with the first event, i.e. on the first upstream byte
			setServerTiming(w, rs)
			h := w.Header()
			h.Set("Content-Type", "text/event-stream")
			h.Set("Cache-Control", "no-cache")
			h.Set("X-Accel-Buffering", "no")
			w.WriteHeader(http.StatusOK)
			wrote = true
		}
		_ = rc.SetWriteDeadline(time.Now().Add(lim.WriteDeadline)) // not supported on every transport: best effort
		if _, err := w.Write(b); err != nil {
			return err
		}
		return rc.Flush()
	}
	finish := func(result string) { m.total.WithLabelValues(result).Inc() }
	fail := func(code, msg, result string) {
		finish(result)
		if !wrote {
			writeErr(w, http.StatusBadGateway, "server_error", code, msg)
			return
		}
		// Mid-stream failure protocol (ADR-26): error event, terminal [DONE], close.
		e := `{"error":{"message":` + strconv.Quote(msg) + `,"type":"server_error","code":"` + code + `"}}`
		out := sse.AppendEvent(nil, "", []byte(e))
		out = sse.AppendEvent(out, "", []byte("[DONE]"))
		_ = flush(out)
	}

	first := true
	for {
		ev, err := dec.Next()
		recvd := time.Now()
		if err != nil {
			switch {
			case body.over:
				fail("stream_too_large", "stream exceeded the size limit", "too_large")
			case errors.Is(err, sse.ErrEventTooLarge):
				fail("event_too_large", "upstream event exceeded the size limit", "event_too_large")
			case ctx.Err() != nil && r.Context().Err() != nil:
				finish("client_gone")
			case errors.Is(ctx.Err(), context.DeadlineExceeded):
				fail("stream_timeout", "stream exceeded the time limit", "timeout")
			case ctx.Err() != nil:
				fail("upstream_stalled", "upstream stopped sending data", "idle")
			case errors.Is(err, io.EOF):
				fail("upstream_incomplete", "upstream ended the stream without [DONE]", "no_done")
			default:
				fail("upstream_error", "upstream stream failed", "upstream_error")
			}
			return
		}
		if ev.HasData {
			if bytes.Equal(ev.Data, doneMarker) {
				if err := flush(ev.Raw); err != nil {
					finish("client_gone")
					return
				}
				m.events.Inc()
				m.bytes.Add(float64(len(ev.Raw)))
				finish("ok")
				return
			}
			if _, err := sc.Scan(ev.Data); err != nil {
				fail("bad_upstream_event", "upstream sent a malformed event", "bad_event")
				return
			}
			if err := a.swalker.Event(ev.Data, sc.Locs); err != nil {
				fail("blocked", "stream blocked by policy", "blocked")
				return
			}
		}
		// Forward the exact bytes received (comments and keep-alives included).
		if err := flush(ev.Raw); err != nil {
			finish("client_slow_or_gone")
			return // the deferred cancel() stops the upstream: no more tokens are paid for
		}
		m.events.Inc()
		m.bytes.Add(float64(len(ev.Raw)))
		held := time.Since(recvd)
		m.added.Observe(held.Seconds())
		if rs != nil {
			rs.eventsOut++
			rs.addedStream += held.Nanoseconds()
			if us := uint32(held.Microseconds()); us > rs.holdMaxUS {
				rs.holdMaxUS = us
			}
		}
		if first {
			first = false
			m.ttfe.Observe(time.Since(start).Seconds())
		}
	}
}

var doneMarker = []byte("[DONE]")
