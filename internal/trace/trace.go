// Package trace provides arrival processes for the open-loop load generator:
// a Poisson process, and a replay of the public BurstGPT trace scaled to a
// target mean rate (burst structure preserved).
package trace

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Arrivals yields successive arrival offsets from the start of the run.
type Arrivals interface {
	// Next returns the offset of the next arrival; ok=false when exhausted.
	Next() (offset time.Duration, ok bool)
}

// ---- Poisson ---------------------------------------------------------------

// Poisson is a homogeneous Poisson arrival process (exponential gaps).
type Poisson struct {
	rate float64
	r    *rand.Rand
	t    float64 // seconds
}

// NewPoisson returns a Poisson process with the given mean rate (events/s).
func NewPoisson(rate float64, seed int64) *Poisson {
	return &Poisson{rate: rate, r: rand.New(rand.NewPCG(uint64(seed), 0xa5a5a5a5))}
}

func (p *Poisson) Next() (time.Duration, bool) {
	p.t += -math.Log(1-p.r.Float64()) / p.rate
	return time.Duration(p.t * float64(time.Second)), true
}

// ---- BurstGPT replay -------------------------------------------------------

// Trace is a finite, sorted list of arrival offsets, optionally with the
// recorded response length (tokens) of each request.
type Trace struct {
	offsets  []time.Duration
	RespToks []int // aligned with offsets; nil if the trace had no such column
	period   time.Duration
	i        int
	lap      int
}

// Stats describes what was loaded.
type Stats struct {
	Rows         int
	OrigDuration time.Duration
	OrigMeanRate float64
	ScaleFactor  float64 // new time = old time * ScaleFactor
	Jittered     bool    // integer-second timestamps were spread within their second
}

// LoadBurstGPT reads a BurstGPT-style CSV and rescales arrival times so the
// mean rate equals targetRate while preserving burst structure.
//
// UNVERIFIED SCHEMA: the loader expects a header row containing (case-
// insensitive) "Timestamp" and, optionally, "Response tokens". IMPLEMENTATION_
// PLAN WP0.3 says to verify the trace's real schema and licence at import time;
// this environment had no network access to the dataset, so this importer is
// tested only on synthetic files and FAILS LOUDLY on a header it does not
// recognise rather than guessing. Verify against the real file before the
// first published run (docs/phases/P0.md, open items).
//
// maxRows <= 0 means no limit.
func LoadBurstGPT(path string, targetRate float64, seed int64, maxRows int) (*Trace, *Stats, error) {
	if targetRate <= 0 {
		return nil, nil, errors.New("trace: targetRate must be > 0")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	cr := csv.NewReader(f)
	cr.FieldsPerRecord = -1
	hdr, err := cr.Read()
	if err != nil {
		return nil, nil, fmt.Errorf("trace: reading header: %w", err)
	}
	tsCol, respCol := -1, -1
	for i, h := range hdr {
		switch strings.ToLower(strings.TrimSpace(h)) {
		case "timestamp":
			tsCol = i
		case "response tokens", "response_tokens":
			respCol = i
		}
	}
	if tsCol < 0 {
		return nil, nil, fmt.Errorf("trace: no Timestamp column in header %q; refusing to guess", hdr)
	}

	type row struct {
		t    float64
		resp int
	}
	var rows []row
	allInt := true
	for maxRows <= 0 || len(rows) < maxRows {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("trace: row %d: %w", len(rows)+2, err)
		}
		if tsCol >= len(rec) {
			return nil, nil, fmt.Errorf("trace: row %d: short record", len(rows)+2)
		}
		ts, err := strconv.ParseFloat(strings.TrimSpace(rec[tsCol]), 64)
		if err != nil || ts < 0 || math.IsNaN(ts) || math.IsInf(ts, 0) {
			return nil, nil, fmt.Errorf("trace: row %d: bad timestamp %q", len(rows)+2, rec[tsCol])
		}
		if ts != math.Trunc(ts) {
			allInt = false
		}
		rw := row{t: ts}
		if respCol >= 0 && respCol < len(rec) {
			rw.resp, _ = strconv.Atoi(strings.TrimSpace(rec[respCol]))
		}
		rows = append(rows, rw)
	}
	if len(rows) < 2 {
		return nil, nil, errors.New("trace: need at least 2 rows")
	}
	if allInt {
		// Timestamps have 1 s resolution: spread requests uniformly within their
		// second so a scaled replay is not a train of simultaneous arrivals.
		r := rand.New(rand.NewPCG(uint64(seed), 0x5eed))
		for i := range rows {
			rows[i].t += r.Float64()
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].t < rows[j].t })
	t0, t1 := rows[0].t, rows[len(rows)-1].t
	if t1 <= t0 {
		return nil, nil, errors.New("trace: zero duration")
	}
	origMean := float64(len(rows)) / (t1 - t0)
	scale := origMean / targetRate // seconds-per-original-second
	tr := &Trace{offsets: make([]time.Duration, len(rows))}
	if respCol >= 0 {
		tr.RespToks = make([]int, len(rows))
	}
	for i, rw := range rows {
		tr.offsets[i] = time.Duration((rw.t - t0) * scale * float64(time.Second))
		if respCol >= 0 {
			tr.RespToks[i] = rw.resp
		}
	}
	tr.period = tr.offsets[len(tr.offsets)-1] + time.Duration(float64(time.Second)/targetRate)
	return tr, &Stats{Rows: len(rows), OrigDuration: time.Duration((t1 - t0) * float64(time.Second)),
		OrigMeanRate: origMean, ScaleFactor: scale, Jittered: allInt}, nil
}

// Next replays the trace, wrapping around (with a period offset) if the run is
// longer than the scaled trace.
func (t *Trace) Next() (time.Duration, bool) {
	off := t.offsets[t.i] + time.Duration(t.lap)*t.period
	t.i++
	if t.i == len(t.offsets) {
		t.i = 0
		t.lap++
	}
	return off, true
}

// Len is the number of recorded arrivals.
func (t *Trace) Len() int { return len(t.offsets) }

// RespTokens returns the recorded response length of the arrival that Next
// most recently returned, or 0 if unknown.
func (t *Trace) RespTokens() int {
	if t.RespToks == nil {
		return 0
	}
	i := t.i - 1
	if i < 0 {
		i = len(t.RespToks) - 1
	}
	return t.RespToks[i]
}
