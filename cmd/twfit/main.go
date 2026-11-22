// Command twfit fits the Phase 0 capacity model from twload run summaries:
//
//	cores = R * c_r + E * c_e        (ARCHITECTURE §12.1)
//
// where R is requests/s, E is events/s, c_r is CPU-seconds per request and c_e
// is CPU-seconds per event. It needs runs that vary events-per-response
// independently of rate, otherwise the two terms are not separable.
//
//	twfit [-w1-rate 20000 -w1-events 64] RUN_DIR [RUN_DIR ...]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
)

type summary struct {
	RunID         string  `json:"run_id"`
	AchievedRate  float64 `json:"achieved_rate_per_s"`
	EventsPerSec  float64 `json:"events_per_s"`
	WindowSecs    float64 `json:"window_seconds"`
	SUTCPUSeconds float64 `json:"sut_cpu_seconds"`
	Valid         bool    `json:"valid"`
}

func main() {
	w1r := flag.Float64("w1-rate", 20000, "target request rate for the sizing prediction")
	w1e := flag.Float64("w1-events", 64, "events per response for the sizing prediction")
	requireValid := flag.Bool("require-valid", false, "refuse runs flagged invalid (rig runs); laptop shape runs are usually invalid")
	flag.Parse()
	if flag.NArg() < 3 {
		fmt.Fprintln(os.Stderr, "usage: twfit [flags] RUN_DIR RUN_DIR RUN_DIR ... (≥ 3 runs; vary events/response)")
		os.Exit(2)
	}
	var rows []summary
	for _, d := range flag.Args() {
		b, err := os.ReadFile(filepath.Join(d, "summary.json"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "twfit:", err)
			os.Exit(1)
		}
		var s summary
		if err := json.Unmarshal(b, &s); err != nil {
			fmt.Fprintln(os.Stderr, "twfit:", d, err)
			os.Exit(1)
		}
		if s.SUTCPUSeconds <= 0 || s.WindowSecs <= 0 {
			fmt.Fprintf(os.Stderr, "twfit: %s has no SUT CPU measurement (run twload with -sut-metrics)\n", d)
			os.Exit(1)
		}
		if *requireValid && !s.Valid {
			fmt.Fprintf(os.Stderr, "twfit: %s is flagged invalid\n", d)
			os.Exit(1)
		}
		rows = append(rows, s)
	}

	// Least squares for y = a*x1 + b*x2 (no intercept), y = SUT cores.
	var s11, s12, s22, s1y, s2y, syy float64
	for _, r := range rows {
		y, x1, x2 := r.SUTCPUSeconds/r.WindowSecs, r.AchievedRate, r.EventsPerSec
		s11 += x1 * x1
		s12 += x1 * x2
		s22 += x2 * x2
		s1y += x1 * y
		s2y += x2 * y
		syy += y * y
	}
	det := s11*s22 - s12*s12
	if math.Abs(det) < 1e-9*s11*s22 {
		fmt.Fprintln(os.Stderr, "twfit: runs are collinear (events/response did not vary independently of rate); cannot separate c_r from c_e")
		os.Exit(1)
	}
	cr := (s22*s1y - s12*s2y) / det
	ce := (s11*s2y - s12*s1y) / det

	var ssRes, ssTot, mean float64
	for _, r := range rows {
		mean += r.SUTCPUSeconds / r.WindowSecs
	}
	mean /= float64(len(rows))
	fmt.Printf("%-24s %10s %12s %10s %10s %10s\n", "run", "req/s", "events/s", "cores", "fitted", "resid")
	for _, r := range rows {
		y := r.SUTCPUSeconds / r.WindowSecs
		f := cr*r.AchievedRate + ce*r.EventsPerSec
		ssRes += (y - f) * (y - f)
		ssTot += (y - mean) * (y - mean)
		fmt.Printf("%-24s %10.0f %12.0f %10.3f %10.3f %+10.3f\n", r.RunID, r.AchievedRate, r.EventsPerSec, y, f, y-f)
	}
	r2 := 1 - ssRes/ssTot
	fmt.Printf("\nc_r = %.1f µs CPU per request     c_e = %.2f µs CPU per event     R² = %.3f (n=%d)\n", cr*1e6, ce*1e6, r2, len(rows))
	if cr < 0 || ce < 0 {
		fmt.Println("WARNING: a negative coefficient means the fit is ill-conditioned (too few or too similar runs); do not use it.")
	}
	cores := *w1r * (cr + *w1e*ce)
	fmt.Printf("prediction at %.0f req/s x %.0f events/response: %.1f cores busy (%.2f M events/s)\n", *w1r, *w1e, cores, *w1r**w1e/1e6)
	fmt.Println("(null-proxy floor only; the real gateway adds inspection on top. Fit from laptop runs is shape-only.)")
}
