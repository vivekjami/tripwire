package trace

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPoissonMeanRate(t *testing.T) {
	p := NewPoisson(20000, 1)
	var last time.Duration
	n := 0
	for {
		off, _ := p.Next()
		if off > 2*time.Second {
			break
		}
		if off < last {
			t.Fatal("arrivals not monotone")
		}
		last = off
		n++
	}
	if rate := float64(n) / 2; math.Abs(rate-20000)/20000 > 0.02 {
		t.Fatalf("mean rate %.0f, want ~20000", rate)
	}
}

func writeCSV(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "trace.csv")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadBurstGPTScalesAndKeepsBursts(t *testing.T) {
	var b strings.Builder
	b.WriteString("Timestamp,Model,Request tokens,Response tokens,Total tokens,Log Type\n")
	// seconds 0..99; second 50 is a 40-request burst, others 1 request
	n := 0
	for s := 0; s < 100; s++ {
		k := 1
		if s == 50 {
			k = 40
		}
		for j := 0; j < k; j++ {
			fmt.Fprintf(&b, "%d,ChatGPT,10,%d,%d,Conversation log\n", s, 20+n%5, 30+n%5)
			n++
		}
	}
	tr, st, err := LoadBurstGPT(writeCSV(t, b.String()), 1000, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	if st.Rows != n || !st.Jittered {
		t.Fatalf("stats %+v", st)
	}
	if tr.RespToks == nil || tr.RespToks[0] < 20 {
		t.Fatal("response tokens not loaded")
	}
	// mean rate after scaling must be the target
	last, _ := tr.offsets[len(tr.offsets)-1], 0
	mean := float64(tr.Len()) / last.Seconds()
	if math.Abs(mean-1000)/1000 > 0.02 {
		t.Fatalf("scaled mean rate %.1f, want 1000", mean)
	}
	// burst preserved: the busiest 1/100th of the span holds far more than average
	span := last / 100
	peak := 0
	j := 0
	for i := range tr.offsets {
		for tr.offsets[i]-tr.offsets[j] > span {
			j++
		}
		peak = max(peak, i-j+1)
	}
	if avg := float64(tr.Len()) / 100; float64(peak) < 5*avg {
		t.Fatalf("burst flattened: peak window %d vs avg %.1f", peak, avg)
	}
	// wrap-around yields monotone offsets
	prev := time.Duration(-1)
	for i := 0; i < tr.Len()*2+5; i++ {
		off, _ := tr.Next()
		if off < prev {
			t.Fatalf("non-monotone at %d after wrap", i)
		}
		prev = off
	}
}

func TestLoadBurstGPTFailsLoudly(t *testing.T) {
	cases := map[string]string{
		"no timestamp col": "a,b\n1,2\n1,2\n",
		"bad ts":           "Timestamp\nx\n2\n",
		"too few rows":     "Timestamp\n1\n",
		"zero duration":    "Timestamp\n1.5\n1.5\n",
	}
	for name, body := range cases {
		if _, _, err := LoadBurstGPT(writeCSV(t, body), 100, 1, 0); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, _, err := LoadBurstGPT(writeCSV(t, "Timestamp\n1\n2\n"), 0, 1, 0); err == nil {
		t.Error("expected error for rate 0")
	}
}
