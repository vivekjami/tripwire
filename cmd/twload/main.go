// Command twload is the open-loop load generator and ground-truth checker.
//
//	twload run  [flags]            run a load test, write results/<run-id>/
//	twload diff -base DIR -test DIR   subtract a baseline run's percentiles (null proxy vs direct)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vivekjami/tripwire/internal/hist"
	"github.com/vivekjami/tripwire/internal/load"
	"github.com/vivekjami/tripwire/internal/mock"
	"github.com/vivekjami/tripwire/internal/trace"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "run":
		os.Exit(runCmd(os.Args[2:]))
	case "diff":
		os.Exit(diffCmd(os.Args[2:]))
	case "timer":
		os.Exit(timerCmd())
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: twload run [flags] | twload diff -base DIR -test DIR | twload timer")
	os.Exit(2)
}

func runCmd(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var (
		target   = fs.String("target", "http://127.0.0.1:9200", "base URL of the system under test")
		mode     = fs.String("mode", "http", "http | mcp | connections | lineage")
		surface  = fs.String("surface", "chat", "chat | responses")
		h2c      = fs.Bool("h2c", false, "speak h2c to the target")
		tlsCA    = fs.String("tls-ca", "", "PEM roots to trust for an https target (certificate verification stays on)")
		h2tls    = fs.Bool("h2", false, "https target: use HTTP/2 via ALPN instead of HTTP/1.1")
		rate     = fs.Float64("rate", 1000, "mean arrival rate, requests/s (Poisson unless --trace)")
		dur      = fs.Duration("duration", 30*time.Second, "measurement window")
		warm     = fs.Duration("warmup", 5*time.Second, "warm-up (discarded)")
		seed     = fs.Int64("seed", 1, "seed (arrivals, request mix, stream content)")
		spin     = fs.Duration("spin-margin", 0, "dispatcher busy-waits this long before each arrival (0 = 1.5ms default; tune with `twload timer`)")
		maxIn    = fs.Int("max-inflight", 200000, "concurrency cap")
		runID    = fs.String("run-id", "", "run id (default: UTC timestamp)")
		out      = fs.String("out", "bench/results", "results root; output goes to <out>/<run-id>/")
		traceF   = fs.String("trace", "", "BurstGPT-style CSV to replay, rescaled to --rate")
		traceMax = fs.Int("trace-max-rows", 0, "limit trace rows loaded (0 = all)")

		streamFrac = fs.Float64("stream-frac", 1.0, "fraction of requests that stream")
		events     = fs.Int("events", 64, "approximate events per response")
		gap        = fs.String("gap", "const:20ms", "mock inter-event gap")
		chunk      = fs.String("chunk", "token", "mock chunking: token | per-char | random:P | boundary | adversarial")
		inject     = fs.String("inject", "", "classes to inject, e.g. PCI.PAN:1,SECRET.AWS_ACCESS_KEY:1")
		injectFrac = fs.Float64("inject-frac", 0, "fraction of requests carrying injections")
		fault      = fs.String("fault", "", "mock fault, kind@event[:stall=DUR], e.g. reset@10")
		faultFrac  = fs.Float64("fault-frac", 0, "fraction of requests carrying the fault")

		mcpVer      = fs.String("mcp-version", "2025-11-25", "MCP protocol revision to speak")
		mcpTool     = fs.String("mcp-tool", "get_customer", "tool to call")
		mcpMismatch = fs.Float64("mcp-mismatch-frac", 0, "fraction of 2026-07-28 requests with a wrong Mcp-Name header (must be rejected)")
		idle        = fs.Int("idle-conns", 0, "open this many idle TCP connections (connection storm)")

		gt      = fs.String("ground-truth", "", "twmock ground-truth JSONL (enables leak/alteration checks)")
		emitLog = fs.String("emit-log", "", "twmock emit-timestamp CSV (enables per-event latency join)")
		emitSmp = fs.Float64("emit-sample", 1.0, "must equal twmock --emit-sample")
		chkSmp  = fs.Float64("check-sample", 0.05, "fraction of streams fully parsed and checked")
		sut     = fs.String("sut-metrics", "", "SUT /metrics URL (records SUT CPU seconds)")
		mockSt  = fs.String("mock-stats", "", "twmock /_tw/stats URL")
		gomax   = fs.Int("gomaxprocs", 0, "GOMAXPROCS (0 = default)")
	)
	_ = fs.Parse(args)
	if *gomax > 0 {
		runtime.GOMAXPROCS(*gomax)
	}

	cfg := load.Config{
		RunID: *runID, Target: *target, Mode: *mode, Surface: *surface, H2C: *h2c, TLSCA: *tlsCA, H2TLS: *h2tls,
		Rate: *rate, Duration: *dur, Warmup: *warm, Seed: *seed, MaxInflight: *maxIn, SpinMargin: *spin,
		StreamFrac: *streamFrac, Events: *events, Gap: *gap, Chunk: *chunk, InjectFrac: *injectFrac, FaultFrac: *faultFrac,
		MCPVersion: *mcpVer, MCPTool: *mcpTool, MCPMismatchFrac: *mcpMismatch, IdleConns: *idle,
		GTLog: *gt, EmitLog: *emitLog, EmitSample: *emitSmp, CheckSample: *chkSmp,
		SUTMetrics: *sut, MockStats: *mockSt,
	}
	var err error
	if cfg.Inject, err = parseInject(*inject); err != nil {
		return fail(err)
	}
	if cfg.Fault, err = parseFault(*fault); err != nil {
		return fail(err)
	}
	if *traceF != "" {
		tr, st, err := trace.LoadBurstGPT(*traceF, *rate, *seed, *traceMax)
		if err != nil {
			return fail(err)
		}
		cfg.Arrivals = tr
		fmt.Printf("trace: %d rows, original mean %.3f req/s over %s, scale x%.6g (jittered within second: %v)\n",
			st.Rows, st.OrigMeanRate, st.OrigDuration.Round(time.Second), st.ScaleFactor, st.Jittered)
	}
	r, err := load.New(cfg)
	if err != nil {
		return fail(err)
	}
	// New applied defaults (including the run id) to its own copy; mirror it.
	cfg.RunID = r.RunID()
	cfg.OutDir = filepath.Join(*out, cfg.RunID)
	r.SetOutDir(cfg.OutDir)

	sum, err := r.Run()
	if err != nil {
		return fail(err)
	}
	printSummary(sum, cfg.OutDir)
	if !sum.Valid {
		fmt.Fprintln(os.Stderr, "RUN INVALID:", strings.Join(sum.InvalidReasons, "; "))
		return 3
	}
	if g := sum.GroundTruth; g != nil && (g.SpansLeaked > 0 || g.Altered > 0) {
		return 4 // checks failed; nonzero so scripts notice
	}
	return 0
}

func parseInject(s string) ([]mock.Inject, error) {
	if s == "" {
		return nil, nil
	}
	var out []mock.Inject
	for _, item := range strings.Split(s, ",") {
		cls, n, ok := strings.Cut(item, ":")
		c := 1
		if ok {
			var err error
			if c, err = strconv.Atoi(n); err != nil {
				return nil, fmt.Errorf("--inject %q: bad count", item)
			}
		}
		out = append(out, mock.Inject{Class: cls, Count: c})
	}
	return out, nil
}

func parseFault(s string) (*mock.Fault, error) {
	if s == "" {
		return nil, nil
	}
	spec, opts, _ := strings.Cut(s, ":")
	kind, at, ok := strings.Cut(spec, "@")
	if !ok {
		return nil, fmt.Errorf("--fault %q: want kind@event[:stall=DUR]", s)
	}
	n, err := strconv.Atoi(at)
	if err != nil {
		return nil, fmt.Errorf("--fault %q: bad event index", s)
	}
	f := &mock.Fault{Kind: kind, AtEvent: n}
	if v, ok := strings.CutPrefix(opts, "stall="); ok {
		f.Stall = v
	}
	return f, nil
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "twload:", err)
	return 1
}

func us(v int64) string {
	switch {
	case v >= 1_000_000:
		return fmt.Sprintf("%.2fs", float64(v)/1e6)
	case v >= 1000:
		return fmt.Sprintf("%.2fms", float64(v)/1e3)
	}
	return fmt.Sprintf("%dµs", v)
}

func line(name string, p hist.Percentiles) {
	if p.Count == 0 {
		return
	}
	fmt.Printf("  %-22s n=%-9d p50=%-9s p99=%-9s p99.9=%-9s max=%s\n", name, p.Count, us(p.P50), us(p.P99), us(p.P999), us(p.Max))
}

func printSummary(s *load.Summary, dir string) {
	fmt.Printf("run %s  mode=%s surface=%s target=%s\n", s.RunID, s.Mode, s.Surface, s.Target)
	fmt.Printf("  offered %.0f/s -> achieved %.0f/s over %.1fs  (completed %d of %d offered, abandoned %d)\n",
		s.OfferedRate, s.AchievedRate, s.WindowSecs, s.Completed, s.OfferedCount, s.Abandoned)
	fmt.Printf("  events %d (%.0f/s)   generator CPU %.0f%%", s.Events, s.EventsPerSec, 100*s.GenCPUUtil)
	if s.SUTCPUSeconds > 0 {
		fmt.Printf("   SUT CPU %.2f core-s (%.2f cores)", s.SUTCPUSeconds, s.SUTCPUSeconds/s.WindowSecs)
	}
	fmt.Println()
	line("request_total", s.ReqTotal)
	line("time_to_headers", s.TTFH)
	line("time_to_first_event", s.TTFE)
	line("event_delay", s.EventDelay)
	line("dispatch_lag (gen)", s.DispatchLag)
	if len(s.Errors) > 0 {
		b, _ := json.Marshal(s.Errors)
		fmt.Printf("  errors: %s\n", b)
	}
	if m := s.MCP; m != nil {
		fmt.Printf("  mcp: ok=%d mismatch_rejected=%d mismatch_ACCEPTED=%d\n", m.OK, m.MismatchRejected, m.MismatchAccepted)
	}
	if g := s.GroundTruth; g != nil {
		fmt.Printf("  ground truth: checked=%d with_injection=%d spans=%d LEAKED=%d altered=%d parse_err=%d incomplete=%d\n",
			g.Checked, g.WithInjection, g.SpansTotal, g.SpansLeaked, g.Altered, g.ParseErrors, g.Incomplete)
	}
	if s.Mock != nil {
		fmt.Printf("  mock emit jitter: p50=%s p99=%s max=%s\n", us(s.Mock.Jitter.P50), us(s.Mock.Jitter.P99), us(s.Mock.Jitter.Max))
	}
	fmt.Printf("  valid=%v  results: %s\n", s.Valid, dir)
}

// diffCmd subtracts the baseline run's percentiles from the test run's. This
// is "added latency": the same measurement through a pass-through proxy and
// direct, differenced percentile by percentile. Percentile subtraction is an
// approximation of the true distribution of differences; for tails it is a
// conservative estimate when baseline variance is small, and the rig report
// states this next to every chart.
func diffCmd(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	base := fs.String("base", "", "baseline run directory (e.g. direct to mock)")
	test := fs.String("test", "", "test run directory (e.g. through the proxy)")
	_ = fs.Parse(args)
	if *base == "" || *test == "" {
		return fail(fmt.Errorf("both -base and -test required"))
	}
	for _, name := range []string{"event_delay", "time_to_first_event", "time_to_headers", "request_total"} {
		hb, err1 := hist.Load(filepath.Join(*base, "raw", name+".hdr"))
		ht, err2 := hist.Load(filepath.Join(*test, "raw", name+".hdr"))
		if err1 != nil || err2 != nil || hb.TotalCount() == 0 || ht.TotalCount() == 0 {
			continue
		}
		fmt.Printf("%s (test − base):\n", name)
		for _, p := range []float64{50, 90, 99, 99.9} {
			b, t := hb.ValueAtPercentile(p), ht.ValueAtPercentile(p)
			fmt.Printf("  p%-5g base=%-9s test=%-9s added=%s\n", p, us(b), us(t), us(t-b))
		}
	}
	return 0
}

// timerCmd measures this host's sleep overshoot so --spin-margin can be set from
// data (and so a noisy host is visible before a benchmark session starts).
func timerCmd() int {
	for _, d := range []time.Duration{50 * time.Microsecond, 200 * time.Microsecond, time.Millisecond, 2 * time.Millisecond} {
		var over []int64
		for i := 0; i < 2000; i++ {
			t0 := time.Now()
			time.Sleep(d)
			over = append(over, int64(time.Since(t0)-d)/1000)
		}
		sort.Slice(over, func(i, j int) bool { return over[i] < over[j] })
		fmt.Printf("sleep %-6v overshoot p50=%-8s p99=%-8s max=%s\n", d, us(over[len(over)/2]), us(over[len(over)*99/100]), us(over[len(over)-1]))
	}
	fmt.Println("set --spin-margin above the p99 overshoot of the ~1ms sleep (the dispatcher sleeps only when the gap is > 2x the margin)")
	return 0
}
