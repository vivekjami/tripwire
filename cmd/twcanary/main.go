// Command twcanary is the rig noise canary (bench/RUNBOOK.md pre-flight 4): a
// fixed CPU loop and a loopback TCP ping-pong, reported as JSON. A host whose
// canary is more than 5 % off its stored baseline is too noisy to benchmark.
//
//	twcanary [-baseline bench/noise-baseline.json] [-write]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sort"
	"time"
)

type result struct {
	CPUNsPerOp    float64 `json:"cpu_ns_per_op"`       // best of 7 rounds (min filters interference)
	LoopbackRTTUS float64 `json:"loopback_rtt_p50_us"` // median of 20 000 1-byte round trips
}

func main() {
	basePath := flag.String("baseline", "bench/noise-baseline.json", "baseline file")
	write := flag.Bool("write", false, "store this measurement as the baseline")
	flag.Parse()
	r := result{CPUNsPerOp: cpu(), LoopbackRTTUS: rtt()}
	out, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(out))
	if *write {
		if err := os.WriteFile(*basePath, append(out, '\n'), 0o644); err != nil { //nolint:gosec // public result
			fmt.Fprintln(os.Stderr, "twcanary:", err)
			os.Exit(1)
		}
		return
	}
	b, err := os.ReadFile(*basePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "twcanary: no baseline:", err)
		os.Exit(2)
	}
	var base result
	if err := json.Unmarshal(b, &base); err != nil {
		fmt.Fprintln(os.Stderr, "twcanary:", err)
		os.Exit(1)
	}
	dc := 100 * (r.CPUNsPerOp/base.CPUNsPerOp - 1)
	dn := 100 * (r.LoopbackRTTUS/base.LoopbackRTTUS - 1)
	fmt.Printf("drift vs baseline: cpu %+.1f%%  loopback %+.1f%%\n", dc, dn)
	if math.Abs(dc) > 5 || math.Abs(dn) > 5 {
		fmt.Println("CANARY: more than 5% off baseline: host too noisy to benchmark")
		os.Exit(3)
	}
}

var sink uint64

func cpu() float64 {
	best := math.MaxFloat64
	for round := 0; round < 7; round++ {
		const n = 20_000_000
		x := uint64(88172645463325252)
		t := time.Now()
		for i := 0; i < n; i++ {
			x ^= x << 13
			x ^= x >> 7
			x ^= x << 17
		}
		sink += x
		if v := float64(time.Since(t).Nanoseconds()) / n; v < best {
			best = v
		}
	}
	return best
}

func rtt() float64 {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return 0
	}
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	buf := make([]byte, 1)
	d := make([]float64, 0, 20000)
	for i := 0; i < 20000; i++ {
		t := time.Now()
		_, _ = c.Write(buf)
		_, _ = io.ReadFull(c, buf)
		d = append(d, float64(time.Since(t).Nanoseconds())/1e3)
	}
	sort.Float64s(d)
	return d[len(d)/2]
}
