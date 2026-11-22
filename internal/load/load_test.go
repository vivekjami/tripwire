package load

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vivekjami/tripwire/internal/groundtruth"
	"github.com/vivekjami/tripwire/internal/mock"
	"github.com/vivekjami/tripwire/internal/nullproxy"
)

type rig struct {
	mockURL, proxyURL string
	gt, emit          string
	srv               *mock.Server
}

// newRig wires mock -> null proxy in-process, with ground-truth and emit logs.
func newRig(t *testing.T, mcfg func(*mock.Config)) *rig {
	t.Helper()
	dir := t.TempDir()
	gtw, err := groundtruth.NewWriter(filepath.Join(dir, "gt.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ew, err := groundtruth.NewEmitWriter(filepath.Join(dir, "emit.csv"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := mock.Config{GroundTruth: gtw, Emit: ew, EmitSample: 1}
	if mcfg != nil {
		mcfg(&cfg)
	}
	srv := mock.New(cfg)
	mts := httptest.NewServer(srv.Handler())
	p, err := nullproxy.New(nullproxy.Config{Upstreams: []string{mts.URL}}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	go p.Serve(ctx, ln, false, nil)
	t.Cleanup(func() { cancel(); mts.Close(); gtw.Close(); ew.Close() })
	return &rig{mockURL: mts.URL, proxyURL: "http://" + ln.Addr().String(), gt: filepath.Join(dir, "gt.jsonl"), emit: filepath.Join(dir, "emit.csv"), srv: srv}
}

func baseCfg(r *rig) Config {
	return Config{
		Target: r.proxyURL, Rate: 200, Duration: 2 * time.Second, Warmup: 500 * time.Millisecond, Seed: 4,
		StreamFrac: 1, Events: 24, Gap: "const:5ms", GTLog: r.gt, EmitLog: r.emit, EmitSample: 1, CheckSample: 1,
		MockStats: r.mockURL + "/_tw/stats", SpinMargin: 2 * time.Millisecond,
	}
}

// The harness's ground-truth checker must SEE leaks when nothing redacts, and
// must see none when the stream is untouched benign text. This is the control
// that gives "0 leaks" in later phases any meaning.
func TestPassThroughLeaksEveryInjectedSpan(t *testing.T) {
	for _, chunk := range []string{"token", "adversarial"} {
		r := newRig(t, nil)
		cfg := baseCfg(r)
		cfg.Chunk = chunk
		cfg.Inject = []mock.Inject{{Class: "PCI.PAN", Count: 2}, {Class: "SECRET.AWS_ACCESS_KEY", Count: 1}}
		cfg.InjectFrac = 0.5
		cfg.OutDir = t.TempDir()
		run, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		s, err := run.Run()
		if err != nil {
			t.Fatal(err)
		}
		g := s.GroundTruth
		if g == nil || g.Checked < 100 {
			t.Fatalf("%s: ground truth not checked: %+v", chunk, g)
		}
		if g.WithInjection == 0 || g.SpansLeaked != g.SpansTotal {
			t.Errorf("%s: pass-through must leak every span: total=%d leaked=%d", chunk, g.SpansTotal, g.SpansLeaked)
		}
		if g.Altered != 0 || g.ParseErrors != 0 || g.Incomplete != 0 || g.MissingGT != 0 {
			t.Errorf("%s: benign alteration/parse/incomplete/missing must be 0: %+v", chunk, g)
		}
		if s.EventDelay.Count == 0 || s.EventDelay.P50 > 20_000 {
			t.Errorf("%s: event delay join broken: %+v", chunk, s.EventDelay)
		}
		if len(s.Errors) != 0 {
			t.Errorf("%s: errors %v", chunk, s.Errors)
		}
		for _, f := range []string{"summary.json", "env.json", "raw/request_total.hdr", "raw/event_delay.hdr", "raw/dispatch_lag.hdr", "raw/config.json"} {
			if _, err := os.Stat(filepath.Join(cfg.OutDir, f)); err != nil {
				t.Errorf("%s: missing output %s", chunk, f)
			}
		}
		var back Summary
		b, _ := os.ReadFile(filepath.Join(cfg.OutDir, "summary.json"))
		if err := json.Unmarshal(b, &back); err != nil || back.RunID != s.RunID {
			t.Errorf("summary.json unreadable: %v", err)
		}
	}
}

func TestResponsesSurfaceAndNonStream(t *testing.T) {
	r := newRig(t, nil)
	cfg := baseCfg(r)
	cfg.Surface = "responses"
	cfg.StreamFrac = 0.5
	cfg.Inject = []mock.Inject{{Class: "PII.CONTACT.EMAIL", Count: 1}}
	cfg.InjectFrac = 1
	run, _ := New(cfg)
	s, err := run.Run()
	if err != nil {
		t.Fatal(err)
	}
	g := s.GroundTruth
	if g == nil || g.Checked < 100 || g.SpansLeaked != g.SpansTotal || g.ParseErrors != 0 || len(s.Errors) != 0 {
		t.Fatalf("responses surface check failed: gt=%+v errors=%v", g, s.Errors)
	}
}

func TestFaultsAreCountedNotCrashed(t *testing.T) {
	r := newRig(t, nil)
	cfg := baseCfg(r)
	cfg.Fault = &mock.Fault{Kind: "reset", AtEvent: 3}
	cfg.FaultFrac = 1
	cfg.GTLog, cfg.EmitLog, cfg.CheckSample = "", "", 0
	run, _ := New(cfg)
	s, err := run.Run()
	if err != nil {
		t.Fatal(err)
	}
	if s.Completed != 0 {
		t.Errorf("streams reset at event 3 reported as completed: %d", s.Completed)
	}
	var total int64
	for _, n := range s.Errors {
		total += n
	}
	if total < 100 {
		t.Errorf("faults not counted as errors: %v", s.Errors)
	}
}

func TestMCPModes(t *testing.T) {
	for _, ver := range []string{"2026-07-28", "2025-11-25"} {
		r := newRig(t, nil)
		cfg := baseCfg(r)
		cfg.Mode, cfg.MCPVersion, cfg.MCPMismatchFrac = "mcp", ver, 0.3
		cfg.Inject = []mock.Inject{{Class: "PCI.PAN", Count: 1}}
		cfg.InjectFrac = 1
		cfg.Events, cfg.Gap = 12, "none"
		run, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		s, err := run.Run()
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Errors) != 0 {
			t.Fatalf("%s: errors %v", ver, s.Errors)
		}
		if s.MCP.OK < 100 {
			t.Fatalf("%s: only %d ok calls", ver, s.MCP.OK)
		}
		if ver == "2026-07-28" {
			// the mock is a conformant server: every mismatching request must be rejected
			if s.MCP.MismatchRejected == 0 || s.MCP.MismatchAccepted != 0 {
				t.Errorf("%s: mismatch handling wrong: %+v", ver, s.MCP)
			}
		} else if s.MCP.MismatchRejected+s.MCP.MismatchAccepted != 0 {
			t.Errorf("%s: header-mismatch applies only to the stateless revision: %+v", ver, s.MCP)
		}
		if g := s.GroundTruth; g == nil || g.SpansLeaked != g.SpansTotal || g.SpansTotal == 0 {
			t.Errorf("%s: MCP ground truth: %+v", ver, g)
		}
	}
}

func TestConnectionStorm(t *testing.T) {
	r := newRig(t, nil)
	cfg := baseCfg(r)
	cfg.Mode, cfg.IdleConns = "connections", 500
	cfg.Rate, cfg.Duration, cfg.Warmup = 0, time.Second, 0
	cfg.GTLog, cfg.EmitLog = "", ""
	run, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := run.Run()
	if err != nil {
		t.Fatal(err)
	}
	if s.IdleConns != 500 || s.IdleFailed != 0 || s.ConnectTime == nil || s.ConnectTime.Count != 500 {
		t.Fatalf("storm: open=%d failed=%d connect=%+v", s.IdleConns, s.IdleFailed, s.ConnectTime)
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	cases := map[string]Config{
		"no target":     {Rate: 1, Duration: time.Second},
		"no rate":       {Target: "http://x", Duration: time.Second},
		"no duration":   {Target: "http://x", Rate: 1},
		"bad mode":      {Target: "http://x", Rate: 1, Duration: time.Second, Mode: "nope"},
		"lineage later": {Target: "http://x", Rate: 1, Duration: time.Second, Mode: "lineage"},
		"log no sample": {Target: "http://x", Rate: 1, Duration: time.Second, GTLog: "x"},
	}
	for name, c := range cases {
		if _, err := New(c); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestInvalidRunIsFlagged(t *testing.T) {
	// A one-slot inflight cap against a slow upstream forces the generator
	// behind schedule: the run must report itself invalid, not quietly succeed.
	srv := mock.New(mock.Config{DefaultGap: "const:50ms", DefaultEvents: 8})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	run, _ := New(Config{Target: ts.URL, Rate: 500, Duration: time.Second, Seed: 1, Events: 8, Gap: "const:50ms", StreamFrac: 1, MaxInflight: 1})
	s, err := run.Run()
	if err != nil {
		t.Fatal(err)
	}
	if s.Valid || len(s.InvalidReasons) == 0 {
		t.Fatalf("a generator pinned behind schedule must invalidate the run: lag p99=%dµs valid=%v", s.DispatchLag.P99, s.Valid)
	}
	_ = http.StatusOK
}

// The h2c (cleartext HTTP/2, prior knowledge) client path must really speak h2.
func TestH2CClient(t *testing.T) {
	srv := mock.New(mock.Config{DefaultGap: "none", DefaultEvents: 8})
	var proto atomic.Value
	h := srv.Handler()
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" {
			proto.Store(r.Proto)
		}
		h.ServeHTTP(w, r)
	}))
	ts.Config.Protocols = new(http.Protocols)
	ts.Config.Protocols.SetHTTP1(true)
	ts.Config.Protocols.SetUnencryptedHTTP2(true)
	ts.Start()
	defer ts.Close()
	run, err := New(Config{Target: ts.URL, H2C: true, Rate: 100, Duration: time.Second, Seed: 1, Events: 8, Gap: "none", StreamFrac: 1})
	if err != nil {
		t.Fatal(err)
	}
	s, err := run.Run()
	if err != nil {
		t.Fatal(err)
	}
	if s.Completed < 50 || len(s.Errors) != 0 {
		t.Fatalf("h2c run: completed=%d errors=%v", s.Completed, s.Errors)
	}
	if got, _ := proto.Load().(string); got != "HTTP/2.0" {
		t.Fatalf("server saw %q, want HTTP/2.0", got)
	}
}
