package hist

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentRecordAndMerge(t *testing.T) {
	h := New(1_000_000, 3)
	var wg sync.WaitGroup
	const workers, per = 32, 5000
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				h.Record(int64(1 + (w*per+i)%1000))
			}
		}(w)
	}
	wg.Wait()
	m := h.Merge()
	if m.TotalCount() != workers*per {
		t.Fatalf("lost samples: %d != %d", m.TotalCount(), workers*per)
	}
	p := Summarize(m)
	if p.P50 < 480 || p.P50 > 520 || p.P99 < 980 || p.Max != 1000 || p.Min != 1 {
		t.Fatalf("percentiles off for uniform 1..1000: %+v", p)
	}
}

func TestClampsOutOfRangeInsteadOfDropping(t *testing.T) {
	h := New(1000, 3)
	h.Record(-5)
	h.Record(0)
	h.Record(5_000_000)
	m := h.Merge()
	if m.TotalCount() != 3 {
		t.Fatalf("outliers dropped: %d", m.TotalCount())
	}
	if m.Max() < 1000 || m.Min() != 1 {
		t.Fatalf("clamping wrong: min=%d max=%d", m.Min(), m.Max())
	}
}

// The coordinated-omission-relevant property: merging histograms keeps the tail.
// Averaging per-run p99s would not (IMPLEMENTATION_PLAN §12.3).
func TestMergeKeepsTailUnlikeAveragedPercentiles(t *testing.T) {
	a, b := New(10_000_000, 3), New(10_000_000, 3)
	for i := 0; i < 1000; i++ {
		a.Record(100)
	}
	for i := 0; i < 990; i++ {
		b.Record(100)
	}
	for i := 0; i < 10; i++ {
		b.Record(1_000_000)
	}
	pa, pb := Summarize(a.Merge()), Summarize(b.Merge())
	avg := (pa.P999 + pb.P999) / 2
	merged := a.Merge()
	merged.Merge(b.Merge())
	if got := merged.ValueAtPercentile(99.9); got <= avg {
		t.Fatalf("merged p99.9 %d should exceed the (wrong) average of per-run p99.9s %d", got, avg)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	h := New(1_000_000, 3)
	for i := int64(1); i <= 1000; i++ {
		h.Record(i * 10)
	}
	p := filepath.Join(t.TempDir(), "x.hdr")
	if err := Save(p, h.Merge()); err != nil {
		t.Fatal(err)
	}
	back, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if back.TotalCount() != 1000 || back.ValueAtPercentile(99) != h.Merge().ValueAtPercentile(99) {
		t.Fatalf("round trip mismatch: n=%d", back.TotalCount())
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.hdr")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestSummarizeEmpty(t *testing.T) {
	if p := Summarize(New(1000, 3).Merge()); p.Count != 0 || p.P99 != 0 {
		t.Fatalf("empty summary not zero: %+v", p)
	}
}

func BenchmarkRecordParallel(b *testing.B) {
	h := New(1_000_000, 3)
	b.RunParallel(func(pb *testing.PB) {
		i := int64(0)
		for pb.Next() {
			i++
			h.Record(i%100000 + 1)
		}
	})
}
