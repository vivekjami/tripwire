package load

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/vivekjami/tripwire/internal/envinfo"
	"github.com/vivekjami/tripwire/internal/groundtruth"
	"github.com/vivekjami/tripwire/internal/hist"
	"github.com/vivekjami/tripwire/internal/mock"
)

// Invalidation thresholds from IMPLEMENTATION_PLAN §12.1: a run is discarded if
// the generator itself was the bottleneck.
const (
	maxGenCPUUtil   = 0.60
	maxDispatchLagP = 200 // µs, p99
)

// GTSummary is the ground-truth verdict for the checked streams.
type GTSummary struct {
	Checked       int64            `json:"checked"`
	WithInjection int64            `json:"with_injection"`
	SpansTotal    int64            `json:"spans_total"`
	SpansLeaked   int64            `json:"spans_leaked"`
	StreamsLeaked int64            `json:"streams_leaked"`
	LeaksByClass  map[string]int64 `json:"leaks_by_class,omitempty"`
	Altered       int64            `json:"benign_altered"`
	ParseErrors   int64            `json:"parse_errors"`
	Incomplete    int64            `json:"incomplete"`
	MissingGT     int64            `json:"missing_ground_truth"`
}

// Summary is the machine-readable result of a run (summary.json).
type Summary struct {
	RunID   string    `json:"run_id"`
	Started time.Time `json:"started_utc"`
	Mode    string    `json:"mode"`
	Surface string    `json:"surface"`
	Target  string    `json:"target"`

	OfferedRate  float64 `json:"offered_rate_per_s"`  // configured
	OfferedCount int64   `json:"offered_count"`       // requests scheduled in the window
	Completed    int64   `json:"completed"`           // successful requests in the window
	AchievedRate float64 `json:"achieved_rate_per_s"` // completed / wall
	WindowSecs   float64 `json:"window_seconds"`
	Abandoned    int64   `json:"abandoned_after_drain"`
	Undispatched int64   `json:"undispatched"` // scheduled in the window but never sent: the generator fell behind

	Errors map[string]int64 `json:"errors,omitempty"`

	ReqTotal    hist.Percentiles `json:"request_total"`   // intended send -> response complete
	TTFH        hist.Percentiles `json:"time_to_headers"` // intended send -> headers received
	TTFE        hist.Percentiles `json:"time_to_first_event"`
	DispatchLag hist.Percentiles `json:"dispatch_lag"` // actual send - intended send: generator health
	EventDelay  hist.Percentiles `json:"event_delay"`  // client receive - mock emit, per event (needs EmitLog)
	NegDelays   int64            `json:"event_delay_negative_samples,omitempty"`

	Events       int64             `json:"events_received"`
	EventsPerSec float64           `json:"events_per_s"`
	IdleConns    int               `json:"idle_conns_open,omitempty"`
	IdleFailed   int64             `json:"idle_conns_failed,omitempty"`
	ConnectTime  *hist.Percentiles `json:"idle_connect_time,omitempty"`

	GenCPUSeconds float64 `json:"gen_cpu_seconds"`
	GenCPUUtil    float64 `json:"gen_cpu_util"` // cpu / (wall * GOMAXPROCS)
	SUTCPUSeconds float64 `json:"sut_cpu_seconds,omitempty"`

	MCP *struct {
		OK               int64 `json:"ok"`
		MismatchRejected int64 `json:"mismatch_rejected"`
		MismatchAccepted int64 `json:"mismatch_accepted"`
	} `json:"mcp,omitempty"`

	GroundTruth *GTSummary  `json:"ground_truth,omitempty"`
	Mock        *mock.Stats `json:"mock_stats,omitempty"`

	Valid          bool     `json:"valid"`
	InvalidReasons []string `json:"invalid_reasons,omitempty"`
}

func doReq(ctx context.Context, method, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

func mockBase(statsURL string) string {
	return strings.TrimSuffix(statsURL, "/_tw/stats")
}

func (r *Runner) summarize(started time.Time, wall, genCPU, sutCPU float64, abandoned int64) *Summary {
	cfg := r.cfg
	// Make the mock flush its buffered logs, then fetch its stats.
	var mst *mock.Stats
	if cfg.MockStats != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if resp, err := doReq(ctx, http.MethodPost, mockBase(cfg.MockStats)+"/_tw/flush"); err == nil {
			_ = resp.Body.Close()
		}
		if resp, err := doReq(ctx, http.MethodGet, cfg.MockStats); err == nil {
			var st mock.Stats
			if json.NewDecoder(resp.Body).Decode(&st) == nil {
				mst = &st
			}
			_ = resp.Body.Close()
		}
	}

	eventDelay := hist.New(histMaxUS, 3)
	r.joinEmit(eventDelay)
	r.eventDelayH = eventDelay

	s := &Summary{
		RunID: cfg.RunID, Started: started.UTC(), Mode: cfg.Mode, Surface: cfg.Surface, Target: cfg.Target,
		OfferedRate: cfg.Rate, OfferedCount: r.offered.Load(), Completed: r.completed.Load(),
		WindowSecs: wall, Abandoned: abandoned, Undispatched: r.undispatched.Load(), Errors: r.errs,
		ReqTotal: hist.Summarize(r.reqTotal.Merge()), TTFH: hist.Summarize(r.ttfh.Merge()),
		TTFE: hist.Summarize(r.ttfe.Merge()), DispatchLag: hist.Summarize(r.lag.Merge()),
		EventDelay: hist.Summarize(eventDelay.Merge()), NegDelays: r.negDelays.Load(),
		Events: r.events.Load(), GenCPUSeconds: genCPU, SUTCPUSeconds: sutCPU, Mock: mst,
		IdleFailed: r.idleFail.Load(), IdleConns: len(r.idle),
	}
	if len(r.errs) == 0 {
		s.Errors = nil
	}
	if wall > 0 {
		s.AchievedRate = float64(s.Completed) / wall
		s.EventsPerSec = float64(s.Events) / wall
		s.GenCPUUtil = genCPU / (wall * float64(runtime.GOMAXPROCS(0)))
	}
	if cfg.Mode == "connections" || cfg.IdleConns > 0 {
		p := hist.Summarize(r.connect.Merge())
		s.ConnectTime = &p
	}
	if cfg.Mode == "mcp" {
		s.MCP = &struct {
			OK               int64 `json:"ok"`
			MismatchRejected int64 `json:"mismatch_rejected"`
			MismatchAccepted int64 `json:"mismatch_accepted"`
		}{r.mcpOK.Load(), r.mcpRej.Load(), r.mcpAcc.Load()}
	}
	s.GroundTruth = r.groundTruth()

	s.Valid = true
	if s.GenCPUUtil > maxGenCPUUtil {
		s.Valid = false
		s.InvalidReasons = append(s.InvalidReasons, fmt.Sprintf("generator CPU %.0f%% > %.0f%% (generator was the bottleneck)", 100*s.GenCPUUtil, 100*maxGenCPUUtil))
	}
	if s.Undispatched > 0 {
		s.Valid = false
		s.InvalidReasons = append(s.InvalidReasons, fmt.Sprintf("%d scheduled arrivals were never sent (generator pinned at max-inflight or behind schedule)", s.Undispatched))
	}
	if s.DispatchLag.Count > 0 && s.DispatchLag.P99 > maxDispatchLagP {
		s.Valid = false
		s.InvalidReasons = append(s.InvalidReasons, fmt.Sprintf("dispatch lag p99 %d µs > %d µs (generator jitter)", s.DispatchLag.P99, maxDispatchLagP))
	}
	return s
}

// joinEmit joins client receive times with mock emit times per event.
func (r *Runner) joinEmit(out *hist.Sharded) {
	if r.cfg.EmitLog == "" || len(r.recv) == 0 {
		return
	}
	emit, err := groundtruth.LoadEmit(r.cfg.EmitLog)
	if err != nil {
		r.mu.Lock()
		r.errs["emit_log_unreadable: "+err.Error()]++
		r.mu.Unlock()
		return
	}
	for id, recv := range r.recv {
		em := emit[id]
		for i := 0; i < len(recv) && i < len(em); i++ {
			if em[i] == 0 {
				continue
			}
			d := recv[i] - em[i]
			if d < 0 {
				r.negDelays.Add(1)
				d = 0
			}
			out.Record(d / 1000)
		}
	}
}

func (r *Runner) groundTruth() *GTSummary {
	if r.cfg.GTLog == "" || len(r.checks) == 0 {
		return nil
	}
	gtm, err := groundtruth.Load(r.cfg.GTLog)
	g := &GTSummary{LeaksByClass: map[string]int64{}}
	if err != nil {
		g.MissingGT = int64(len(r.checks))
		return g
	}
	for _, it := range r.checks {
		gt := gtm[it.id]
		if gt == nil {
			g.MissingGT++
			continue
		}
		g.Checked++
		if it.parseErr {
			g.ParseErrors++
			continue
		}
		if !it.complete {
			g.Incomplete++
		}
		if len(gt.Spans) > 0 {
			g.WithInjection++
			g.SpansTotal += int64(len(gt.Spans))
		}
		res := groundtruth.Check(gt, it.text)
		if len(res.Leaks) > 0 {
			g.StreamsLeaked++
		}
		for _, l := range res.Leaks {
			g.SpansLeaked++
			g.LeaksByClass[l.Class]++
		}
		if res.Altered && gt.Fault == "" {
			g.Altered++
		}
	}
	if len(g.LeaksByClass) == 0 {
		g.LeaksByClass = nil
	}
	return g
}

// writeResults writes env.json, summary.json and the raw histograms.
func (r *Runner) writeResults(s *Summary) error {
	raw := filepath.Join(r.cfg.OutDir, "raw")
	if err := os.MkdirAll(raw, 0o750); err != nil {
		return err
	}
	env := envinfo.Capture()
	if err := writeJSON(filepath.Join(r.cfg.OutDir, "env.json"), env); err != nil {
		return err
	}
	for name, h := range map[string]*hist.Sharded{
		"request_total": r.reqTotal, "time_to_headers": r.ttfh, "time_to_first_event": r.ttfe, "dispatch_lag": r.lag,
	} {
		if err := hist.Save(filepath.Join(raw, name+".hdr"), h.Merge()); err != nil {
			return err
		}
	}
	// event_delay is joined post hoc; saved when present.
	if r.eventDelayH != nil && s.EventDelay.Count > 0 {
		if err := hist.Save(filepath.Join(raw, "event_delay.hdr"), r.eventDelayH.Merge()); err != nil {
			return err
		}
	}
	cfg := r.cfg
	cfg.Arrivals = nil
	cfg.Bearer = "" // results are committed and may be public: a credential is never written
	cfg.OutDir = envinfo.ScrubHome(cfg.OutDir)
	cfg.GTLog = envinfo.ScrubHome(cfg.GTLog)
	cfg.EmitLog = envinfo.ScrubHome(cfg.EmitLog)
	if err := writeJSON(filepath.Join(raw, "config.json"), cfg); err != nil {
		return err
	}
	if len(r.errs) > 0 {
		keys := make([]string, 0, len(r.errs))
		for k := range r.errs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b bytes.Buffer
		for _, k := range keys {
			fmt.Fprintf(&b, "%s,%d\n", k, r.errs[k])
		}
		if err := os.WriteFile(filepath.Join(raw, "errors.csv"), b.Bytes(), 0o600); err != nil {
			return err
		}
	}
	return writeJSON(filepath.Join(r.cfg.OutDir, "summary.json"), s)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
