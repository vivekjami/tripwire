package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/ch-go"

	"github.com/vivekjami/tripwire/internal/envinfo"
	"github.com/vivekjami/tripwire/internal/lineage"
	"github.com/vivekjami/tripwire/internal/obs"
	"github.com/vivekjami/tripwire/internal/sysutil"
)

// lineageProbe is `twload run -mode lineage`: it drives lineage.Emit directly at
// a target rate through the real pipeline into a sink and reports what the
// pipeline sustained (IMPLEMENTATION_PLAN WP1.6, ARCHITECTURE §10.7 claim 1).
// With -sink null it measures the pipeline alone; with -sink clickhouse it is
// the early ingest probe (committed rows must equal emitted - dropped).
func lineageProbe(args []string) int {
	fs := flag.NewFlagSet("lineage", flag.ExitOnError)
	var (
		rate    = fs.Float64("rate", 1_000_000, "target events/s")
		dur     = fs.Duration("duration", 30*time.Second, "measurement duration")
		sinkK   = fs.String("sink", "null", "null | clickhouse")
		chAddr  = fs.String("ch-addr", "127.0.0.1:9000", "ClickHouse native address")
		chComp  = fs.String("ch-compression", "lz4", "none | lz4")
		ring    = fs.Int("ring", 1<<18, "ring slots")
		batch   = fs.Int("batch-rows", 100_000, "rows per block")
		flush   = fs.Duration("flush", 750*time.Millisecond, "flush interval")
		writers = fs.Int("writers", 2, "writer goroutines / connections")
		prod    = fs.Int("producers", 4, "producer goroutines")
		runID   = fs.String("run-id", "", "run id")
		out     = fs.String("out", "bench/results", "results root")
	)
	_ = fs.Parse(args)
	if *runID == "" {
		*runID = time.Now().UTC().Format("20060102T150405Z") + "-lineage"
	}
	_, _ = sysutil.RaiseNoFile()

	var sink lineage.Sink = &lineage.NullSink{}
	if *sinkK == "clickhouse" {
		comp := ch.CompressionLZ4
		if *chComp == "none" {
			comp = ch.CompressionDisabled
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cs, err := lineage.NewCHSink(ctx, lineage.CHConfig{Addr: *chAddr, Compression: comp, Node: *runID, Conns: *writers})
		cancel()
		if err != nil {
			return fail(fmt.Errorf("clickhouse: %w", err))
		}
		sink = cs
	}
	reg := obs.NewRegistry()
	p := lineage.New(lineage.Config{RingSize: *ring, BatchRows: *batch, FlushEvery: *flush, Writers: *writers, Registry: reg}, sink)
	ids := lineage.NewIDGen(1)

	cpu0 := sysutil.CPUSeconds()
	start := time.Now()
	deadline := start.Add(*dur)
	var samples [][]time.Duration
	var smu sync.Mutex
	var maxDepth atomic.Int64
	var wg sync.WaitGroup
	perProd := *rate / float64(*prod)
	for i := 0; i < *prod; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local []time.Duration
			n := 0
			next := time.Now()
			gap := time.Duration(float64(time.Second) / perProd)
			for time.Now().Before(deadline) {
				// open loop with catch-up: emit everything that is due, then sleep
				for now := time.Now(); !next.After(now); next = next.Add(gap) {
					e := lineage.NewEvent(lineage.KindRequest)
					r := &e.Request
					r.TenantID, r.AgentID, r.Method = "probe", "agent-probe", "POST"
					r.TS, r.EventID, r.Surface, r.Status = now, ids.Next(), obs.SurfaceChat, 200
					r.BytesIn, r.BytesOut, r.TTotalAddedUS = 512, 2048, 37
					if n++; n&1023 == 0 {
						t0 := time.Now()
						p.Emit(e)
						local = append(local, time.Since(t0))
					} else {
						p.Emit(e)
					}
				}
				if d := time.Until(next); d > 200*time.Microsecond {
					time.Sleep(d / 2)
				}
			}
			smu.Lock()
			samples = append(samples, local)
			smu.Unlock()
		}()
	}
	stopMon := make(chan struct{})
	go func() {
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stopMon:
				return
			case <-t.C:
				if d := int64(p.Depth()); d > maxDepth.Load() {
					maxDepth.Store(d)
				}
			}
		}
	}()
	wg.Wait()
	close(stopMon)
	elapsed := time.Since(start)
	_ = p.Close() // flush the tail so committed can equal emitted
	st := p.Stats()
	cpu := sysutil.CPUSeconds() - cpu0

	var all []time.Duration
	for _, s := range samples {
		all = append(all, s...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	pct := func(q float64) int64 {
		if len(all) == 0 {
			return 0
		}
		return all[int(q*float64(len(all)-1))].Nanoseconds()
	}
	res := map[string]any{
		"run_id": *runID, "mode": "lineage", "sink": *sinkK,
		"target_events_per_s": *rate, "duration_s": elapsed.Seconds(),
		"emitted": st.Emitted, "dropped": st.Dropped, "committed": st.Committed, "failed": st.Failed, "batches": st.Batches,
		"achieved_events_per_s":  float64(st.Emitted+st.Dropped) / elapsed.Seconds(),
		"committed_events_per_s": float64(st.Committed) / elapsed.Seconds(),
		"loss_free":              st.Dropped == 0 && st.Failed == 0 && st.Committed == st.Emitted,
		"enqueue_p50_ns":         pct(0.50), "enqueue_p99_ns": pct(0.99), "enqueue_p999_ns": pct(0.999),
		"ring_slots": *ring, "ring_max_depth": maxDepth.Load(),
		"process_cpu_seconds": cpu, "gomaxprocs": runtime.GOMAXPROCS(0),
		"config": map[string]any{"batch_rows": *batch, "flush": flush.String(), "writers": *writers, "producers": *prod, "compression": *chComp},
	}
	dir := filepath.Join(*out, *runID)
	_ = os.MkdirAll(dir, 0o755)
	envB, _ := json.MarshalIndent(envinfo.Capture(), "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "env.json"), envB, 0o644) //nolint:gosec // public results
	sumB, _ := json.MarshalIndent(res, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "summary.json"), sumB, 0o644) //nolint:gosec // public results
	fmt.Printf("lineage probe %s sink=%s\n  emitted %d dropped %d committed %d failed %d in %.1fs\n  achieved %.0f ev/s, committed %.0f ev/s, enqueue p99 %dns, ring max depth %d/%d, cpu %.1fs\n  results: %s\n",
		*runID, *sinkK, st.Emitted, st.Dropped, st.Committed, st.Failed, elapsed.Seconds(),
		res["achieved_events_per_s"], res["committed_events_per_s"], pct(0.99), maxDepth.Load(), *ring, cpu, dir)
	if *sinkK != "null" {
		fmt.Println("  NOTE: also record ClickHouse part counts / merge pressure / settings (bench/RUNBOOK.md, 'Lineage ingest probe').")
	}
	if st.Dropped > 0 || st.Failed > 0 {
		return 3
	}
	return 0
}
