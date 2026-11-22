package mock

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/vivekjami/tripwire/internal/clock"
	"github.com/vivekjami/tripwire/internal/gen"
	"github.com/vivekjami/tripwire/internal/groundtruth"
	"github.com/vivekjami/tripwire/internal/hist"
)

// Config configures a mock server.
type Config struct {
	DefaultEvents int    // approximate content events per response when the spec omits it
	DefaultGap    string // gap spec when the request omits it
	DefaultChunk  string
	MaxEvents     int // hard cap on events per response

	GroundTruth *groundtruth.Writer
	Emit        *groundtruth.EmitWriter
	EmitSample  float64 // fraction of streams whose emit timestamps are logged

	MCPDefaultVersion string // protocol version assumed when the client sends no MCP-Protocol-Version
	Hostile           bool   // MCP: poisoned results and a rug-pulling tool description
	HostileAfter      int    // tools/list calls before the description mutates
}

// Stats is a snapshot of mock counters, served at /_tw/stats.
type Stats struct {
	StreamsStarted int64            `json:"streams_started"`
	StreamsDone    int64            `json:"streams_done"`
	StreamsActive  int64            `json:"streams_active"`
	EventsEmitted  int64            `json:"events_emitted"`
	Requests       int64            `json:"requests"`
	Jitter         hist.Percentiles `json:"emit_jitter"` // actual emit minus scheduled emit
}

// Server is the mock upstream.
type Server struct {
	cfg Config

	started, done, events, requests atomic.Int64
	idSeq                           atomic.Int64
	listCalls                       atomic.Int64
	stallUntil                      atomic.Int64 // CLOCK_MONOTONIC ns
	jitter                          *hist.Sharded
	sessions                        sessionTable
}

// New constructs a Server, applying defaults.
func New(cfg Config) *Server {
	if cfg.DefaultEvents == 0 {
		cfg.DefaultEvents = 64
	}
	if cfg.DefaultGap == "" {
		cfg.DefaultGap = "const:20ms"
	}
	if cfg.DefaultChunk == "" {
		cfg.DefaultChunk = "token"
	}
	if cfg.MaxEvents == 0 {
		cfg.MaxEvents = 100_000
	}
	if cfg.MCPDefaultVersion == "" {
		cfg.MCPDefaultVersion = "2025-11-25"
	}
	if cfg.HostileAfter == 0 {
		cfg.HostileAfter = 2
	}
	return &Server{cfg: cfg, jitter: hist.New(60_000_000, 3)}
}

// Handler returns the mock's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/chat/completions", s.handleChat)
	mux.HandleFunc("POST /v1/responses", s.handleResponses)
	mux.HandleFunc("GET /v1/models", s.handleModels)
	mux.HandleFunc("POST /mcp", s.handleMCP)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /_tw/stats", s.handleStats)
	mux.HandleFunc("POST /_tw/stall", s.handleStall)
	mux.HandleFunc("POST /_tw/flush", s.handleFlush)
	return mux
}

// Stats returns a snapshot of the counters.
func (s *Server) Stats() Stats {
	st, dn := s.started.Load(), s.done.Load()
	return Stats{
		StreamsStarted: st, StreamsDone: dn, StreamsActive: st - dn,
		EventsEmitted: s.events.Load(), Requests: s.requests.Load(),
		Jitter: hist.Summarize(s.jitter.Merge()),
	}
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.Stats())
}

// handleFlush forces buffered ground-truth and emit logs to disk so a harness
// on the same host can read them while the mock keeps running.
func (s *Server) handleFlush(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.GroundTruth != nil {
		_ = s.cfg.GroundTruth.Flush()
	}
	if s.cfg.Emit != nil {
		_ = s.cfg.Emit.Flush()
	}
	io.WriteString(w, "flushed\n")
}

// handleStall freezes ALL emission and request handling for ?ms=N from now.
// It is how the harness injects a known stall (coordinated-omission test).
func (s *Server) handleStall(w http.ResponseWriter, r *http.Request) {
	ms, err := strconv.Atoi(r.URL.Query().Get("ms"))
	if err != nil || ms < 0 || ms > 60_000 {
		http.Error(w, "ms must be 0..60000", http.StatusBadRequest)
		return
	}
	s.stallUntil.Store(clock.Now() + int64(ms)*int64(time.Millisecond))
	io.WriteString(w, "stalling\n")
}

// waitStall blocks while a stall is in effect.
func (s *Server) waitStall() {
	for {
		d := s.stallUntil.Load() - clock.Now()
		if d <= 0 {
			return
		}
		time.Sleep(time.Duration(d))
	}
}

func (s *Server) handleModels(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"object":"list","data":[{"id":"mock-1","object":"model","created":0,"owned_by":"twmock"}]}`)
}

// ---- planning --------------------------------------------------------------

type plan struct {
	spec   Spec
	text   string
	spans  []groundtruth.Span
	pieces []Piece
	gaps   []time.Duration
	ascii  []bool // per piece: \u-escape non-ASCII
	gt     *groundtruth.Stream
}

func avgRunesPerEvent(mode string) float64 {
	switch {
	case mode == "per-char":
		return 1
	case mode == "boundary", mode == "adversarial":
		return 12
	case len(mode) > 7 && mode[:7] == "random:":
		if p, err := strconv.ParseFloat(mode[7:], 64); err == nil && p > 0 {
			return 1 / p
		}
	}
	return 5
}

func (s *Server) specFrom(raw, surface string) (Spec, error) {
	sp, err := ParseSpec(raw)
	if err != nil {
		return sp, err
	}
	if sp.StreamID == "" {
		sp.StreamID = "m-" + strconv.FormatInt(s.idSeq.Add(1), 10)
	}
	if sp.Events == 0 {
		sp.Events = s.cfg.DefaultEvents
	}
	if sp.Events > s.cfg.MaxEvents {
		return sp, fmt.Errorf("events %d exceeds cap %d", sp.Events, s.cfg.MaxEvents)
	}
	if sp.Gap == "" {
		sp.Gap = s.cfg.DefaultGap
	}
	if sp.Chunk == "" {
		sp.Chunk = s.cfg.DefaultChunk
	}
	return sp, nil
}

func (s *Server) makePlan(sp Spec, surface string) (*plan, error) {
	r := gen.NewRand(sp.seedFor())
	var vals []gen.Value
	for _, in := range sp.Inject {
		g, ok := gen.For(in.Class)
		if !ok {
			return nil, fmt.Errorf("no generator for class %q", in.Class)
		}
		for i := 0; i < in.Count; i++ {
			vals = append(vals, g.Generate(r))
		}
	}
	target := int(float64(sp.Events) * avgRunesPerEvent(sp.Chunk))
	text, spans := buildText(r, target, vals)
	pieces, err := Chunk(text, spans, sp.Chunk, r)
	if err != nil {
		return nil, err
	}
	gd, err := ParseGap(sp.Gap)
	if err != nil {
		return nil, err
	}
	pl := &plan{spec: sp, text: text, spans: spans, pieces: pieces,
		gaps: make([]time.Duration, len(pieces)), ascii: make([]bool, len(pieces))}
	for i := range pieces {
		pl.gaps[i] = gd.Next(r)
		switch sp.Escape {
		case "raw":
		case "ascii":
			pl.ascii[i] = true
		default:
			pl.ascii[i] = r.IntN(2) == 0
		}
	}
	gt := &groundtruth.Stream{
		StreamID: sp.StreamID, Surface: surface, Chunking: sp.Chunk, Seed: sp.seedFor(),
		TextLen: len(text), TextHash: groundtruth.HashText(text), Spans: spans,
		EventEnds: make([]int, len(pieces)),
	}
	if sp.Fault != nil {
		gt.Fault = sp.Fault.Kind
	}
	acc := 0
	for i, p := range pieces {
		acc += p.byteLen()
		gt.EventEnds[i] = acc
	}
	pl.gt = gt
	return pl, nil
}

func (s *Server) recordGT(pl *plan) {
	if s.cfg.GroundTruth != nil {
		_ = s.cfg.GroundTruth.Write(pl.gt)
	}
}

// ---- emission --------------------------------------------------------------

// emitter writes SSE frames on a schedule and records emit timestamps.
type emitter struct {
	s       *Server
	w       http.ResponseWriter
	rc      *http.ResponseController
	sched   []int64
	emit    []int64
	sampled bool
	id      string
}

func (s *Server) newEmitter(w http.ResponseWriter, id string) *emitter {
	e := &emitter{s: s, w: w, rc: http.NewResponseController(w), id: id}
	e.sampled = s.cfg.Emit != nil && groundtruth.Sampled(id, s.cfg.EmitSample)
	return e
}

// send waits until sched (monotonic ns), writes the frame and flushes.
func (e *emitter) send(sched int64, frame []byte) error {
	e.s.waitStall()
	if d := sched - clock.Now(); d > 0 {
		time.Sleep(time.Duration(d))
	}
	_ = e.rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	at := clock.Now()
	if _, err := e.w.Write(frame); err != nil {
		return err
	}
	if err := e.rc.Flush(); err != nil {
		return err
	}
	e.s.events.Add(1)
	e.s.jitter.Record((at - sched) / 1000)
	if e.sampled {
		e.sched = append(e.sched, sched)
		e.emit = append(e.emit, at)
	}
	return nil
}

func (e *emitter) close() {
	if e.sampled && len(e.emit) > 0 {
		e.s.cfg.Emit.WriteStream(e.id, e.sched, e.emit)
	}
}

func sseHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
}

// abortConn kills the connection abruptly (TCP RST where possible).
func abortConn(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if c, _, err := hj.Hijack(); err == nil {
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			_ = c.Close()
			return
		}
	}
	panic(http.ErrAbortHandler)
}

// faultAt returns the fault if it triggers on event index i.
func (pl *plan) faultAt(i int) *Fault {
	if f := pl.spec.Fault; f != nil && f.AtEvent == i {
		return f
	}
	return nil
}
