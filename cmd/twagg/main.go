// Command twagg aggregates repeated twload runs into one row per measurement
// point: runs are grouped by run id with a trailing "-r<N>" stripped.
//
// For each group and metric it reports:
//
//   - the MERGED histogram's p50/p99/p99.9/max (percentiles are never averaged);
//
//   - the across-run mean of per-run p99 with a 95 % Student-t confidence
//     interval (this is the run-to-run reproducibility of the p99, not the
//     precision of a single run);
//
//   - how many runs were flagged valid.
//
//     twagg [-metric event_delay] [-md out.md] [-json out.json] RUN_DIR...
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	hdr "github.com/HdrHistogram/hdrhistogram-go"

	"github.com/vivekjami/tripwire/internal/hist"
)

type runSummary struct {
	RunID         string   `json:"run_id"`
	Rate          float64  `json:"offered_rate_per_s"`
	Achieved      float64  `json:"achieved_rate_per_s"`
	EventsPerSec  float64  `json:"events_per_s"`
	Window        float64  `json:"window_seconds"`
	SUTCPU        float64  `json:"sut_cpu_seconds"`
	GenCPUUtil    float64  `json:"gen_cpu_util"`
	Valid         bool     `json:"valid"`
	InvalidReason []string `json:"invalid_reasons"`
	Metrics       map[string]hist.Percentiles
}

// Row is one aggregated measurement point.
type Row struct {
	Point       string  `json:"point"`
	Metric      string  `json:"metric"`
	Runs        int     `json:"runs"`
	ValidRuns   int     `json:"valid_runs"`
	OfferedRPS  float64 `json:"offered_rps"`
	AchievedRPS float64 `json:"achieved_rps_mean"`
	Count       int64   `json:"merged_count"`
	P50         int64   `json:"merged_p50_us"`
	P99         int64   `json:"merged_p99_us"`
	P999        int64   `json:"merged_p999_us"`
	Max         int64   `json:"merged_max_us"`
	P99Mean     float64 `json:"per_run_p99_mean_us"`
	P99CI95     float64 `json:"per_run_p99_ci95_halfwidth_us"`
	SUTCores    float64 `json:"sut_cores_mean"`
	GenCPU      float64 `json:"gen_cpu_util_mean"`
}

var suffix = regexp.MustCompile(`-r\d+$`)

// tCrit95 is the two-sided 95 % Student-t critical value for df = 1..30.
var tCrit95 = [...]float64{0, 12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
	2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086,
	2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042}

func main() {
	metric := flag.String("metric", "event_delay", "request_total | time_to_headers | time_to_first_event | event_delay | dispatch_lag")
	md := flag.String("md", "", "write a markdown table here")
	js := flag.String("json", "", "write rows as JSON here")
	knee := flag.Bool("knee", false, "treat the runs as a load sweep (names end -L<rate>-r<N>) and print the knee: the highest offered rate (req/s) at which every rate up to it is healthy")
	kneeP99 := flag.Int64("knee-p99-us", 5000, "healthy means merged event_delay p99 at or below this (µs)")
	kneeMin := flag.Float64("knee-achieved", 0.98, "...and achieved/offered at or above this")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: twagg [flags] RUN_DIR...")
		os.Exit(2)
	}
	if *knee {
		os.Exit(findKnee(flag.Args(), *kneeP99, *kneeMin))
	}
	groups := map[string][]string{}
	for _, d := range flag.Args() {
		k := suffix.ReplaceAllString(filepath.Base(filepath.Clean(d)), "")
		groups[k] = append(groups[k], d)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var rows []Row
	for _, k := range keys {
		r, err := aggregate(k, *metric, groups[k])
		if err != nil {
			fmt.Fprintln(os.Stderr, "twagg:", err)
			os.Exit(1)
		}
		rows = append(rows, r)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "| point | runs (valid) | offered req/s | %s merged p50 | p99 | p99.9 | max (µs) | per-run p99 mean ± 95%% CI (µs) | SUT cores | gen CPU |\n", *metric)
	sb.WriteString("|---|---|---|---|---|---|---|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(&sb, "| %s | %d (%d) | %.0f | %d | %d | %d | %d | %.0f ± %.0f | %.2f | %.0f%% |\n",
			r.Point, r.Runs, r.ValidRuns, r.OfferedRPS, r.P50, r.P99, r.P999, r.Max, r.P99Mean, r.P99CI95, r.SUTCores, 100*r.GenCPU)
	}
	fmt.Print(sb.String())
	if *md != "" {
		if err := os.WriteFile(*md, []byte(sb.String()), 0o644); err != nil { //nolint:gosec // results are public
			fmt.Fprintln(os.Stderr, "twagg:", err)
			os.Exit(1)
		}
	}
	if *js != "" {
		b, _ := json.MarshalIndent(rows, "", "  ")
		if err := os.WriteFile(*js, append(b, '\n'), 0o644); err != nil { //nolint:gosec // results are public
			fmt.Fprintln(os.Stderr, "twagg:", err)
			os.Exit(1)
		}
	}
}

func aggregate(point, metric string, dirs []string) (Row, error) {
	row := Row{Point: point, Metric: metric, Runs: len(dirs)}
	merged := hdr.New(1, 3_600_000_000, 3)
	var p99s []float64
	for _, d := range dirs {
		b, err := os.ReadFile(filepath.Join(d, "summary.json"))
		if err != nil {
			return row, err
		}
		var s runSummary
		if err := json.Unmarshal(b, &s); err != nil {
			return row, fmt.Errorf("%s: %w", d, err)
		}
		if s.Valid {
			row.ValidRuns++
		}
		row.OfferedRPS = s.Rate
		row.AchievedRPS += s.Achieved / float64(len(dirs))
		row.GenCPU += s.GenCPUUtil / float64(len(dirs))
		if s.Window > 0 {
			row.SUTCores += s.SUTCPU / s.Window / float64(len(dirs))
		}
		h, err := hist.Load(filepath.Join(d, "raw", metric+".hdr"))
		if err != nil {
			return row, fmt.Errorf("%s: %w", d, err)
		}
		if h.TotalCount() == 0 {
			continue
		}
		merged.Merge(h)
		p99s = append(p99s, float64(h.ValueAtPercentile(99)))
	}
	p := hist.Summarize(merged)
	row.Count, row.P50, row.P99, row.P999, row.Max = p.Count, p.P50, p.P99, p.P999, p.Max
	row.P99Mean, row.P99CI95 = meanCI(p99s)
	return row, nil
}

func meanCI(x []float64) (mean, half float64) {
	n := len(x)
	if n == 0 {
		return 0, 0
	}
	for _, v := range x {
		mean += v / float64(n)
	}
	if n < 2 {
		return mean, math.NaN()
	}
	var ss float64
	for _, v := range x {
		ss += (v - mean) * (v - mean)
	}
	sd := math.Sqrt(ss / float64(n-1))
	t := 1.96
	if n-1 < len(tCrit95) {
		t = tCrit95[n-1]
	}
	return mean, t * sd / math.Sqrt(float64(n))
}

var rateRE = regexp.MustCompile(`-L(\d+)(?:-r\d+)?$`)

// findKnee prints a per-rate health table to stderr and the knee (a single
// integer) to stdout. A rate is healthy when its merged event_delay p99 is at
// most maxP99 µs and it achieved at least minAchieved of the offered rate; the
// knee is the highest rate below the first unhealthy one.
func findKnee(dirs []string, maxP99 int64, minAchieved float64) int {
	byRate := map[int][]string{}
	for _, d := range dirs {
		m := rateRE.FindStringSubmatch(filepath.Base(filepath.Clean(d)))
		if m == nil {
			continue
		}
		var r int
		fmt.Sscanf(m[1], "%d", &r)
		byRate[r] = append(byRate[r], d)
	}
	rates := make([]int, 0, len(byRate))
	for r := range byRate {
		rates = append(rates, r)
	}
	sort.Ints(rates)
	knee := 0
	broken := false
	fmt.Fprintf(os.Stderr, "%8s %6s %12s %10s %8s\n", "req/s", "runs", "ev p99 (µs)", "achieved", "healthy")
	for _, r := range rates {
		row, err := aggregate(fmt.Sprintf("L%d", r), "event_delay", byRate[r])
		if err != nil {
			fmt.Fprintln(os.Stderr, "twagg:", err)
			return 1
		}
		ach := 0.0
		if row.OfferedRPS > 0 {
			ach = row.AchievedRPS / row.OfferedRPS
		}
		ok := row.P99 <= maxP99 && ach >= minAchieved
		fmt.Fprintf(os.Stderr, "%8d %6d %12d %9.1f%% %8v\n", r, row.Runs, row.P99, 100*ach, ok)
		if ok && !broken {
			knee = r
		} else {
			broken = true
		}
	}
	if knee == 0 {
		return 2
	}
	fmt.Println(knee)
	return 0
}
