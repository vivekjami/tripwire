package load

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vivekjami/tripwire/internal/clock"
	"github.com/vivekjami/tripwire/internal/groundtruth"
	"github.com/vivekjami/tripwire/internal/hist"
	"github.com/vivekjami/tripwire/internal/mock"
	"github.com/vivekjami/tripwire/internal/sysutil"
	"github.com/vivekjami/tripwire/internal/trace"
)

const histMaxUS = 600_000_000 // 10 minutes in µs

// Runner executes one load run.
type Runner struct {
	cfg    Config
	client *http.Client
	ctx    context.Context
	cancel context.CancelFunc
	sem    chan struct{}
	wg     sync.WaitGroup
	brPool sync.Pool

	// recorders (microseconds)
	reqTotal, ttfh, ttfe, lag, connect *hist.Sharded
	eventDelayH                        *hist.Sharded

	offered, completed, events, undispatched atomic.Int64
	negDelays                                atomic.Int64

	mu       sync.Mutex
	errs     map[string]int64
	checks   []checkItem
	recv     map[string][]int64
	mcpOK    atomic.Int64
	mcpRej   atomic.Int64 // mismatching request correctly rejected
	mcpAcc   atomic.Int64 // mismatching request WRONGLY accepted
	idle     []net.Conn
	idleFail atomic.Int64

	mcpSessOnce sync.Once
	mcpSessID   string
	mcpSessErr  error
}

type checkItem struct {
	id       string
	text     string
	complete bool
	parseErr bool
}

// outcome is what one request observed.
type outcome struct {
	err        string // "" on success
	hdrAt      int64
	firstEvent int64
	events     int
	recv       []int64
	check      *checkItem
}

// New builds a Runner.
func New(cfg Config) (*Runner, error) {
	cfg.applyDefaults()
	if cfg.Target == "" && cfg.Mode != "lineage" {
		return nil, errors.New("load: Target required")
	}
	if cfg.Mode == "lineage" {
		return nil, errors.New("load: --mode lineage drives the lineage emitter directly and arrives with internal/lineage in Phase 4 (WP1.6/WP4.6); not implemented in Phase 0")
	}
	if cfg.Mode != "http" && cfg.Mode != "mcp" && cfg.Mode != "connections" {
		return nil, fmt.Errorf("load: unknown mode %q", cfg.Mode)
	}
	if cfg.Mode != "connections" && cfg.Rate <= 0 && cfg.Arrivals == nil {
		return nil, errors.New("load: Rate must be > 0")
	}
	if cfg.Duration <= 0 {
		return nil, errors.New("load: Duration must be > 0")
	}
	if (cfg.GTLog != "" || cfg.EmitLog != "") && cfg.EmitSample == 0 && cfg.CheckSample == 0 {
		return nil, errors.New("load: GTLog/EmitLog set but EmitSample and CheckSample are both 0")
	}
	if _, err := sysutil.RaiseNoFile(); err != nil {
		return nil, fmt.Errorf("load: raising RLIMIT_NOFILE: %w", err)
	}
	r := &Runner{
		cfg:      cfg,
		client:   newClient(cfg.H2C),
		sem:      make(chan struct{}, cfg.MaxInflight),
		reqTotal: hist.New(histMaxUS, 3), ttfh: hist.New(histMaxUS, 3), ttfe: hist.New(histMaxUS, 3),
		lag: hist.New(histMaxUS, 3), connect: hist.New(histMaxUS, 3),
		errs: map[string]int64{}, recv: map[string][]int64{},
	}
	r.brPool.New = func() any { return bufio.NewReaderSize(nil, 16<<10) }
	r.ctx, r.cancel = context.WithCancel(context.Background())
	return r, nil
}

// RunID returns the effective run id (defaults applied).
func (r *Runner) RunID() string { return r.cfg.RunID }

// SetOutDir sets where Run writes results (empty disables writing).
func (r *Runner) SetOutDir(d string) { r.cfg.OutDir = d }

// ---- deterministic per-request randomness ---------------------------------

func splitmix(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// unit returns a deterministic uniform [0,1) value for (seed, seq, salt).
func unit(seed, seq int64, salt uint64) float64 {
	return float64(splitmix(uint64(seed)^splitmix(uint64(seq)^salt<<32))>>11) / float64(1<<53)
}

// ---- scheduling ------------------------------------------------------------

// waitUntil blocks until the monotonic clock reaches t. It sleeps for the bulk
// of a long gap and SPINS through the last `margin`, because OS timer wake-ups
// overshoot (about 1 ms on WSL2; tens of µs on tuned bare metal; measure with
// `twload timer`) and the mean gap at 30 K req/s is only 33 µs.
func waitUntil(t int64, margin time.Duration) {
	m := int64(margin)
	for {
		d := t - clock.Now()
		if d <= 0 {
			return
		}
		if d > 2*m {
			time.Sleep(time.Duration(d - m))
		}
	}
}

// Run executes the run and returns its Summary. Files are written to
// cfg.OutDir if set.
func (r *Runner) Run() (*Summary, error) {
	cfg := r.cfg
	arr := cfg.Arrivals
	if arr == nil && cfg.Mode != "connections" {
		arr = trace.NewPoisson(cfg.Rate, cfg.Seed)
	}
	if cfg.IdleConns > 0 || cfg.Mode == "connections" {
		n := cfg.IdleConns
		if n == 0 {
			return nil, errors.New("load: Mode=connections needs IdleConns > 0")
		}
		r.openIdle(n)
		defer func() {
			for _, c := range r.idle {
				_ = c.Close()
			}
		}()
	}

	started := time.Now()
	start := clock.Now()
	warmEnd := start + int64(cfg.Warmup)
	end := warmEnd + int64(cfg.Duration)

	var cpu0, sut0 float64
	var wall0 int64
	snapped := false
	snap := func() {
		cpu0, wall0 = sysutil.CPUSeconds(), clock.Now()
		if cfg.SUTMetrics != "" {
			sut0, _ = scrapeCPU(cfg.SUTMetrics)
		}
		snapped = true
	}
	if cfg.Warmup == 0 {
		snap()
	}

	endTimer := time.NewTimer(time.Duration(max(end-clock.Now(), 0)))
	defer endTimer.Stop()
	if arr != nil {
		for seq := int64(0); ; seq++ {
			off, ok := arr.Next()
			if !ok {
				break
			}
			intended := start + int64(off)
			if intended >= end {
				break
			}
			waitUntil(intended, cfg.SpinMargin)
			if !snapped && intended >= warmEnd {
				snap()
			}
			measure := intended >= warmEnd
			// Acquire an in-flight slot. If the generator is pinned at MaxInflight
			// it falls behind schedule (visible as dispatch lag); it never waits
			// past the end of the window, and arrivals it could not send are
			// counted, so a saturated generator invalidates the run instead of
			// silently reporting a lower offered load.
			acquired := false
			if clock.Now() < end {
				select {
				case r.sem <- struct{}{}:
					acquired = true
				case <-endTimer.C:
				}
			}
			if measure {
				r.offered.Add(1)
			}
			if !acquired {
				if measure {
					r.undispatched.Add(1)
				}
				continue
			}
			ev := 0
			if tr, ok := arr.(*trace.Trace); ok && tr.RespToks != nil {
				// trace-driven response length: 1 token ~ 1 SSE event, clamped
				ev = min(max(tr.RespTokens(), 1), 1024)
			}
			r.wg.Add(1)
			go r.one(seq, intended, measure, ev)
		}
	} else {
		waitUntil(end, cfg.SpinMargin)
	}
	waitUntil(end, cfg.SpinMargin)
	if !snapped {
		snap()
	}
	// window closed: snapshot CPU before draining so drain time is not counted
	cpu1, wall1 := sysutil.CPUSeconds(), clock.Now()
	var sut1 float64
	if cfg.SUTMetrics != "" {
		sut1, _ = scrapeCPU(cfg.SUTMetrics)
	}

	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	abandoned := int64(0)
	select {
	case <-done:
	case <-time.After(cfg.DrainTimeout):
		abandoned = int64(len(r.sem))
		r.cancel()
		<-done
	}

	sum := r.summarize(started, float64(wall1-wall0)/1e9, cpu1-cpu0, sut1-sut0, abandoned)
	if cfg.OutDir != "" {
		if err := r.writeResults(sum); err != nil {
			return sum, err
		}
	}
	return sum, nil
}

func (r *Runner) one(seq int64, intended int64, measure bool, events int) {
	defer func() { <-r.sem; r.wg.Done() }()
	id := r.cfg.RunID + "-" + strconv.FormatInt(seq, 10)
	sendAt := clock.Now()
	var o outcome
	switch r.cfg.Mode {
	case "mcp":
		o = r.doMCP(id, seq, events)
	default:
		o = r.doHTTP(id, seq, events)
	}
	if !measure {
		return
	}
	done := clock.Now()
	r.lag.Record((sendAt - intended) / 1000)
	if o.err != "" {
		r.mu.Lock()
		r.errs[o.err]++
		r.mu.Unlock()
		return
	}
	r.completed.Add(1)
	r.reqTotal.Record((done - intended) / 1000)
	if o.hdrAt != 0 {
		r.ttfh.Record((o.hdrAt - intended) / 1000)
	}
	if o.firstEvent != 0 {
		r.ttfe.Record((o.firstEvent - intended) / 1000)
	}
	r.events.Add(int64(o.events))
	if o.recv != nil || o.check != nil {
		r.mu.Lock()
		if o.recv != nil {
			r.recv[id] = o.recv
		}
		if o.check != nil {
			r.checks = append(r.checks, *o.check)
		}
		r.mu.Unlock()
	}
}

// ---- HTTP (OpenAI-shaped) workload ----------------------------------------

func (r *Runner) specFor(id string, seq int64, events int) mock.Spec {
	c := r.cfg
	if events <= 0 {
		events = c.Events
	}
	sp := mock.Spec{StreamID: id, Events: events, Gap: c.Gap, Chunk: c.Chunk, Seed: c.Seed*1_000_003 + seq + 1}
	if len(c.Inject) > 0 && unit(c.Seed, seq, 11) < c.InjectFrac {
		sp.Inject = c.Inject
	}
	if c.Fault != nil && unit(c.Seed, seq, 13) < c.FaultFrac {
		f := *c.Fault
		sp.Fault = &f
	}
	return sp
}

type chatBody struct {
	Model    string            `json:"model"`
	Stream   bool              `json:"stream"`
	Messages []chatMsg         `json:"messages,omitempty"`
	Input    string            `json:"input,omitempty"`
	Metadata map[string]string `json:"metadata"`
}
type chatMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func (r *Runner) doHTTP(id string, seq int64, events int) outcome {
	c := r.cfg
	stream := unit(c.Seed, seq, 7) < c.StreamFrac
	sp := r.specFor(id, seq, events)
	sj, _ := json.Marshal(sp)
	cb := chatBody{Model: "mock-1", Stream: stream, Metadata: map[string]string{"tw_mock": string(sj)}}
	path := "/v1/chat/completions"
	if c.Surface == "responses" {
		path = "/v1/responses"
		cb.Input = "Say something benign."
	} else {
		cb.Messages = []chatMsg{{Role: "user", Content: "Say something benign."}}
	}
	body, _ := json.Marshal(cb)

	ctx, cancel := context.WithTimeout(r.ctx, c.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Target+path, bytes.NewReader(body))
	if err != nil {
		return outcome{err: "build_request"}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return outcome{err: classifyErr(err)}
	}
	defer resp.Body.Close()
	o := outcome{hdrAt: clock.Now()}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return outcome{err: "status_" + strconv.Itoa(resp.StatusCode)}
	}
	sampled := groundtruth.Sampled(id, c.EmitSample) && c.EmitLog != ""
	check := c.GTLog != "" && groundtruth.Sampled(id+"#check", c.CheckSample)

	if !stream {
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			return outcome{err: classifyErr(err)}
		}
		o.firstEvent = clock.Now()
		o.events = 1
		if check {
			text, err := extractNonStream(c.Surface, b)
			o.check = &checkItem{id: id, text: text, complete: err == nil, parseErr: err != nil}
		}
		return o
	}
	return r.readStream(resp.Body, id, o, sampled, check)
}

// readStream consumes an SSE body, timestamping each event when its blank-line
// terminator is read. Cheap by design: payloads are only copied and parsed for
// the sampled "check" streams.
func (r *Runner) readStream(body io.Reader, id string, o outcome, sampled, check bool) outcome {
	br := r.brPool.Get().(*bufio.Reader)
	br.Reset(body)
	defer func() { br.Reset(nil); r.brPool.Put(br) }()

	var (
		atLineStart = true
		inData      bool
		complete    bool
		payload     []byte
		units       []uint16
		parseErr    bool
	)
	if sampled {
		o.recv = make([]int64, 0, 128)
	}
	for {
		line, err := br.ReadSlice('\n')
		full := errors.Is(err, bufio.ErrBufferFull)
		if err != nil && !full {
			if err != io.EOF {
				o.err = classifyErr(err)
			}
			break
		}
		if atLineStart {
			switch {
			case len(line) == 1 || (len(line) == 2 && line[0] == '\r'): // blank line: event end
				if inData {
					now := clock.Now()
					o.events++
					if o.events == 1 {
						o.firstEvent = now
					}
					if sampled {
						o.recv = append(o.recv, now)
					}
					if check {
						if u, ok, perr := extractEvent(r.cfg.Surface, payload); perr != nil {
							parseErr = true
						} else if ok {
							units = append(units, u...)
						}
						payload = payload[:0]
					}
					inData = false
				}
			case bytes.HasPrefix(line, []byte("data:")):
				inData = true
				v := bytes.TrimLeft(line[5:], " ")
				if bytes.HasPrefix(v, []byte("[DONE]")) {
					complete = true
				}
				if check {
					if full {
						parseErr = true
					} else {
						payload = append(payload[:0], bytes.TrimRight(v, "\r\n")...)
					}
				}
			case bytes.HasPrefix(line, []byte("event:")):
				if bytes.Contains(line, []byte("response.completed")) {
					complete = true
				}
			}
		}
		atLineStart = !full
	}
	if o.err == "" && !complete {
		o.err = "stream_truncated"
	}
	if check && o.err == "" {
		o.check = &checkItem{id: id, text: groundtruth.UnitsToString(units), complete: complete, parseErr: parseErr}
	}
	return o
}

func classifyErr(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected_eof"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "connection reset"):
		return "conn_reset"
	case strings.Contains(s, "connection refused"):
		return "conn_refused"
	case strings.Contains(s, "EOF"):
		return "eof"
	case strings.Contains(s, "too many open files"):
		return "emfile"
	case strings.Contains(s, "cannot assign requested address"):
		return "port_exhaustion"
	}
	return "transport_error"
}

// ---- idle connection storm -------------------------------------------------

func (r *Runner) openIdle(n int) {
	host := strings.TrimPrefix(strings.TrimPrefix(r.cfg.Target, "http://"), "https://")
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 256)
	for i := 0; i < n; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			t0 := clock.Now()
			c, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(r.ctx, "tcp", host)
			if err != nil {
				r.idleFail.Add(1)
				return
			}
			r.connect.Record((clock.Now() - t0) / 1000)
			mu.Lock()
			r.idle = append(r.idle, c)
			mu.Unlock()
		}()
	}
	wg.Wait()
}
