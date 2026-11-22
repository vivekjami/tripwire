package load

// Harness self-validation (IMPLEMENTATION_PLAN WP0.3). These tests exist
// because every later number depends on the harness being correct:
//
//  1. Coordinated omission: a known 500 ms stall MUST show up in p99/p99.9,
//     and a closed-loop control run against the same stall MUST NOT, proving
//     the generator measures what a closed-loop one would hide.
//  2. Generator headroom: against a trivially fast upstream the generator must
//     not be the bottleneck (CPU < 60 %, dispatch-lag p99 < 200 µs).
//  3. Clock join: a known fixed delay injected by a relay must be recovered
//     from the cross-process emit/receive timestamps to within ±50 µs.
//  4. Mock emission jitter is bounded (the mock must not be the noise source).
//
// Thresholds match the plan (60 %, 200 µs, ±50 µs). On WSL2/laptops the
// timer-resolution-bound checks (2 and 3) are the ones that can fail; the
// failure is informative, not a reason to loosen the plan. Set
// TW_SELFCHECK_RELAXED=1 to log instead of fail on those two, which is what
// `make selfcheck-laptop` does; `make selfcheck` (used on the rig) is strict.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/vivekjami/tripwire/internal/clock"
	"github.com/vivekjami/tripwire/internal/hist"
	"github.com/vivekjami/tripwire/internal/mock"
)

var relaxed = os.Getenv("TW_SELFCHECK_RELAXED") == "1"

// check fails strictly, or logs when relaxed (timer-bound checks only).
func check(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if ok {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if relaxed {
		t.Logf("RELAXED (would fail on the rig): %s", msg)
		return
	}
	t.Error(msg)
}

// ---- 1. coordinated omission ----------------------------------------------

func TestSelfCheckCoordinatedOmission(t *testing.T) {
	if testing.Short() {
		t.Skip("self-validation runs ~10 s")
	}
	srv := mock.New(mock.Config{DefaultGap: "none", DefaultEvents: 2})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	const stall = 500 * time.Millisecond
	stallAt := time.Second

	// --- open loop (twload) ---
	time.AfterFunc(stallAt, func() { http.Post(ts.URL+"/_tw/stall?ms=500", "", nil) })
	r, err := New(Config{Target: ts.URL, Rate: 1000, Duration: 3 * time.Second, Seed: 1, Events: 2, Gap: "none"})
	if err != nil {
		t.Fatal(err)
	}
	sum, err := r.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("open loop:   p50=%dµs p99=%dµs p99.9=%dµs max=%dµs (n=%d)", sum.ReqTotal.P50, sum.ReqTotal.P99, sum.ReqTotal.P999, sum.ReqTotal.Max, sum.ReqTotal.Count)
	// ~500 of ~3000 requests arrive during the stall (≈17 %), so p99 sits in the stall tail.
	if min := int64(0.8 * float64(stall.Microseconds())); sum.ReqTotal.P99 < min {
		t.Errorf("open-loop p99 = %dµs, want ≥ %dµs: the stall is being hidden (coordinated omission)", sum.ReqTotal.P99, min)
	}
	if sum.ReqTotal.P999 < int64(0.9*float64(stall.Microseconds())) {
		t.Errorf("open-loop p99.9 = %dµs, want ≥ 90%% of the stall", sum.ReqTotal.P999)
	}

	// --- closed loop control: one request at a time against the same stall ---
	time.AfterFunc(stallAt, func() { http.Post(ts.URL+"/_tw/stall?ms=500", "", nil) })
	h := hist.New(histMaxUS, 3)
	end := time.Now().Add(3 * time.Second)
	body := `{"model":"m","stream":false,"messages":[{"role":"user","content":"x"}],"metadata":{"tw_mock":"{\"events\":2,\"gap\":\"none\"}"}}`
	for time.Now().Before(end) {
		t0 := time.Now()
		resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", stringsReader(body))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		h.Record(time.Since(t0).Microseconds())
	}
	hh := h.Merge()
	t.Logf("closed loop: p50=%dµs p99=%dµs p99.9=%dµs max=%dµs (n=%d)", hh.ValueAtPercentile(50), hh.ValueAtPercentile(99), hh.ValueAtPercentile(99.9), hh.Max(), hh.TotalCount())
	if hh.Max() < int64(0.8*float64(stall.Microseconds())) {
		t.Fatal("control invalid: the closed-loop client never even saw the stall")
	}
	if p99 := hh.ValueAtPercentile(99); p99 > int64(stall.Microseconds())/5 {
		t.Errorf("control invalid: closed-loop p99=%dµs should hide the stall (the point of this test)", p99)
	}
}

func stringsReader(s string) io.Reader { return &sr{s: s} }

type sr struct {
	s string
	i int
}

func (r *sr) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}

// ---- helpers for subprocess mocks ------------------------------------------

var (
	buildOnce sync.Once
	binDir    string
	buildErr  error
)

func twmockBin(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		binDir, buildErr = os.MkdirTemp("", "twbin")
		if buildErr != nil {
			return
		}
		out, err := exec.Command("go", "build", "-o", filepath.Join(binDir, "twmock"), "github.com/vivekjami/tripwire/cmd/twmock").CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("go build twmock: %w\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return filepath.Join(binDir, "twmock")
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// startMock runs twmock as a separate process (so CPU and clocks are genuinely
// cross-process) and waits for it to serve.
func startMock(t *testing.T, args ...string) (addr string) {
	t.Helper()
	addr = freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, twmockBin(t), append([]string{"-listen", addr, "-admin", ""}, args...)...)
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); cmd.Wait() })
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("twmock did not start")
	return ""
}

// ---- 2. generator headroom --------------------------------------------------

func TestSelfCheckGeneratorHeadroom(t *testing.T) {
	if testing.Short() {
		t.Skip("self-validation")
	}
	rate := 10000.0
	if v := os.Getenv("TW_HEADROOM_RATE"); v != "" {
		rate, _ = strconv.ParseFloat(v, 64) // rig: 30000
	}
	addr := startMock(t, "-events", "1", "-gap", "none")
	r, err := New(Config{Target: "http://" + addr, Rate: rate, Duration: 4 * time.Second, Warmup: 2 * time.Second, Seed: 3, Events: 1, Gap: "none"})
	if err != nil {
		t.Fatal(err)
	}
	sum, err := r.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("rate=%.0f achieved=%.0f genCPU=%.0f%% lag p50=%dµs p99=%dµs p99.9=%dµs errors=%v",
		rate, sum.AchievedRate, 100*sum.GenCPUUtil, sum.DispatchLag.P50, sum.DispatchLag.P99, sum.DispatchLag.P999, sum.Errors)
	if len(sum.Errors) > 0 {
		t.Fatalf("errors during headroom run: %v", sum.Errors)
	}
	if sum.AchievedRate < 0.97*rate {
		t.Errorf("achieved %.0f/s < 97%% of offered %.0f/s against a trivially fast upstream", sum.AchievedRate, rate)
	}
	check(t, sum.GenCPUUtil < maxGenCPUUtil, "generator CPU %.0f%% ≥ 60%%", 100*sum.GenCPUUtil)
	check(t, sum.DispatchLag.P99 < maxDispatchLagP, "dispatch lag p99 %dµs ≥ %dµs", sum.DispatchLag.P99, maxDispatchLagP)
}

// ---- 3. clock join ----------------------------------------------------------

// delayRelay is a TCP relay that holds each upstream→client chunk for a fixed
// time, using a busy-wait so the injected delay is exact to a few µs.
func delayRelay(t *testing.T, upstream string, d time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				u, err := net.Dial("tcp", upstream)
				if err != nil {
					c.Close()
					return
				}
				go func() { io.Copy(u, c); u.Close() }()
				buf := make([]byte, 32<<10)
				for {
					n, err := u.Read(buf)
					if n > 0 {
						for deadline := clock.Now() + int64(d); clock.Now() < deadline; {
						}
						if _, werr := c.Write(buf[:n]); werr != nil {
							break
						}
					}
					if err != nil {
						break
					}
				}
				c.Close()
				u.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func TestSelfCheckClockJoin(t *testing.T) {
	if testing.Short() {
		t.Skip("self-validation")
	}
	dir := t.TempDir()
	gt, emit := filepath.Join(dir, "gt.jsonl"), filepath.Join(dir, "emit.csv")
	addr := startMock(t, "-ground-truth", gt, "-emit-log", emit, "-emit-sample", "1", "-gap", "const:15ms", "-events", "30")

	run := func(target string, id string) *Summary {
		r, err := New(Config{RunID: id, Target: "http://" + target, Rate: 20, Duration: 5 * time.Second, Warmup: time.Second, Seed: 9, StreamFrac: 1,
			Events: 30, Gap: "const:15ms", GTLog: gt, EmitLog: emit, EmitSample: 1, CheckSample: 0, MockStats: "http://" + addr + "/_tw/stats", MaxInflight: 1000})
		if err != nil {
			t.Fatal(err)
		}
		s, err := r.Run()
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Errors) > 0 {
			t.Fatalf("%s: errors %v", id, s.Errors)
		}
		return s
	}
	const injected = 2 * time.Millisecond
	base := run(delayRelay(t, addr, 0), "join-base") // relay with no delay: same hop overhead
	test := run(delayRelay(t, addr, injected), "join-delay")

	if base.EventDelay.Count < 500 || test.EventDelay.Count < 500 {
		t.Fatalf("too few joined events: base=%d test=%d", base.EventDelay.Count, test.EventDelay.Count)
	}
	// Sanity of the join itself: delays through a loopback relay must be small and non-negative.
	if base.EventDelay.P50 < 0 || base.EventDelay.P50 > 5000 {
		t.Fatalf("baseline median event delay %dµs is implausible: cross-process clock join is broken", base.EventDelay.P50)
	}
	recovered := test.EventDelay.P50 - base.EventDelay.P50
	t.Logf("injected=%dµs recovered=%dµs (base p50=%dµs, delayed p50=%dµs; negative samples base=%d test=%d)",
		injected.Microseconds(), recovered, base.EventDelay.P50, test.EventDelay.P50, base.NegDelays, test.NegDelays)
	err := recovered - injected.Microseconds()
	if err < 0 {
		err = -err
	}
	check(t, err <= 50, "recovered delay off by %dµs (> ±50µs)", err)
	if err > 500 {
		t.Errorf("recovered delay off by %dµs: the join is broken, not merely noisy", err)
	}
}

// ---- 4. mock emission jitter -------------------------------------------------

func TestSelfCheckMockEmissionJitter(t *testing.T) {
	if testing.Short() {
		t.Skip("self-validation")
	}
	srv := mock.New(mock.Config{DefaultGap: "const:20ms", DefaultEvents: 50})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	r, err := New(Config{Target: ts.URL, Rate: 100, Duration: 3 * time.Second, Warmup: time.Second, Seed: 5, StreamFrac: 1, Events: 50, Gap: "const:20ms", MaxInflight: 5000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(); err != nil {
		t.Fatal(err)
	}
	j := srv.Stats().Jitter
	t.Logf("mock emit jitter at ~200 concurrent streams: p50=%dµs p99=%dµs max=%dµs (n=%d)", j.P50, j.P99, j.Max, j.Count)
	if j.Count < 5000 {
		t.Fatalf("only %d jitter samples", j.Count)
	}
	// Bound chosen to catch a broken scheduler, not to certify the rig: the rig
	// run records this histogram in summary.json (mock_stats.emit_jitter).
	check(t, j.P99 < 2000, "mock emit jitter p99 %dµs ≥ 2000µs", j.P99)
}
