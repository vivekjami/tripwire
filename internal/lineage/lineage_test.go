package lineage

import (
	"context"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	chmig "github.com/vivekjami/tripwire/deploy/ch"
)

func TestRingSingleThreadOrderAndFull(t *testing.T) {
	r := NewRing(4)
	if r.Cap() != 4 {
		t.Fatal(r.Cap())
	}
	var evs [5]*Event
	for i := range evs {
		evs[i] = NewEvent(KindRequest)
		evs[i].Request.EventID = uint64(i)
	}
	for i := 0; i < 4; i++ {
		if !r.Push(evs[i]) {
			t.Fatalf("push %d", i)
		}
	}
	if r.Push(evs[4]) {
		t.Fatal("push into a full ring must fail, not block or overwrite")
	}
	for i := 0; i < 4; i++ {
		e, ok := r.Pop()
		if !ok || e.Request.EventID != uint64(i) {
			t.Fatalf("pop %d: %v %v", i, e, ok)
		}
	}
	if _, ok := r.Pop(); ok {
		t.Fatal("pop from an empty ring")
	}
	// wrap-around many laps
	for lap := 0; lap < 100; lap++ {
		for i := 0; i < 3; i++ {
			if !r.Push(evs[i]) {
				t.Fatal("push after wrap")
			}
		}
		for i := 0; i < 3; i++ {
			if _, ok := r.Pop(); !ok {
				t.Fatal("pop after wrap")
			}
		}
	}
}

// Many producers, one consumer: every pushed event is popped exactly once.
func TestRingMPSCNoLossNoDuplicates(t *testing.T) {
	const producers, per = 8, 50_000
	r := NewRing(1 << 10)
	var pushed, full atomic.Uint64
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				e := NewEvent(KindRequest)
				e.Request.EventID = uint64(p)<<32 | uint64(i)
				for !r.Push(e) {
					full.Add(1)
					time.Sleep(time.Microsecond)
				}
				pushed.Add(1)
			}
		}(p)
	}
	seen := make(map[uint64]bool, producers*per)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for len(seen) < producers*per {
			if e, ok := r.Pop(); ok {
				if seen[e.Request.EventID] {
					t.Errorf("duplicate %x", e.Request.EventID)
					return
				}
				seen[e.Request.EventID] = true
			}
		}
	}()
	wg.Wait()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatalf("consumer stalled at %d/%d", len(seen), producers*per)
	}
	// per-producer FIFO: ids from one producer come out in order is not required by the ring
	// contract across slots, but nothing may be lost.
	if uint64(len(seen)) != pushed.Load() {
		t.Fatalf("lost events: %d popped of %d pushed", len(seen), pushed.Load())
	}
	t.Logf("ring was full %d times (producers backed off)", full.Load())
}

func TestPipelineCommitsEverythingOnClose(t *testing.T) {
	sink := &MemorySink{}
	p := New(Config{RingSize: 1 << 12, BatchRows: 100, FlushEvery: 20 * time.Millisecond, Writers: 2}, sink)
	for i := 0; i < 1000; i++ {
		e := NewEvent(KindRequest)
		e.Request.EventID = uint64(i)
		e.Request.AgentID = "a"
		if !p.Emit(e) {
			t.Fatal("emit failed with room in the ring")
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	st := p.Stats()
	if st.Emitted != 1000 || st.Committed != 1000 || st.Dropped != 0 || st.Failed != 0 {
		t.Fatalf("%+v", st)
	}
	got := sink.Snapshot()
	if len(got) != 1000 {
		t.Fatalf("sink has %d", len(got))
	}
	ids := map[uint64]bool{}
	for _, e := range got {
		ids[e.Request.EventID] = true
	}
	if len(ids) != 1000 {
		t.Fatalf("duplicates or losses: %d distinct", len(ids))
	}
	if p.Emit(NewEvent(KindRequest)) {
		t.Fatal("Emit after Close must be refused")
	}
	if err := p.Close(); err != nil {
		t.Fatal("Close must be idempotent")
	}
}

func TestPipelineFlushesOnInterval(t *testing.T) {
	sink := &MemorySink{}
	p := New(Config{BatchRows: 1_000_000, FlushEvery: 50 * time.Millisecond}, sink)
	defer p.Close()
	for i := 0; i < 10; i++ {
		p.Emit(NewEvent(KindRequest))
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(sink.Snapshot()) < 10 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := len(sink.Snapshot()); n != 10 {
		t.Fatalf("a small batch must flush on the interval, not wait for BatchRows (got %d)", n)
	}
}

func TestEmitNeverBlocksAndCountsDrops(t *testing.T) {
	block := make(chan struct{})
	slow := &blockingSink{block: block}
	p := New(Config{RingSize: 8, BatchRows: 2, FlushEvery: time.Millisecond, Writers: 1}, slow)
	start := time.Now()
	accepted := 0
	for i := 0; i < 10_000; i++ {
		if p.Emit(NewEvent(KindRequest)) {
			accepted++
		}
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("Emit blocked the caller for %v while the sink was stuck", d)
	}
	st := p.Stats()
	if st.Dropped == 0 || st.Emitted != uint64(accepted) || st.Emitted+st.Dropped != 10_000 {
		t.Fatalf("accounting: %+v accepted=%d", st, accepted)
	}
	close(block)
	_ = p.Close()
	if st := p.Stats(); st.Committed != st.Emitted {
		t.Fatalf("everything accepted must be committed after the sink recovers: %+v", st)
	}
}

type blockingSink struct {
	block chan struct{}
	rows  atomic.Int64
}

func (b *blockingSink) WriteBatch(_ context.Context, batch []*Event) error {
	<-b.block
	b.rows.Add(int64(len(batch)))
	return nil
}
func (b *blockingSink) Close() error { return nil }

func TestSinkRetryThenDropAccounting(t *testing.T) {
	sink := &MemorySink{}
	sink.Fail.Store(2) // first two attempts fail, third succeeds
	p := New(Config{BatchRows: 10, FlushEvery: 10 * time.Millisecond, Retries: 3, Writers: 1}, sink)
	for i := 0; i < 10; i++ {
		p.Emit(NewEvent(KindRequest))
	}
	_ = p.Close()
	if st := p.Stats(); st.Committed != 10 || st.Failed != 0 {
		t.Fatalf("retry should have succeeded: %+v", st)
	}
	sink2 := &MemorySink{}
	sink2.Fail.Store(1000)
	p2 := New(Config{BatchRows: 10, FlushEvery: 10 * time.Millisecond, Retries: 1, Writers: 1}, sink2)
	for i := 0; i < 10; i++ {
		p2.Emit(NewEvent(KindRequest))
	}
	_ = p2.Close()
	if st := p2.Stats(); st.Committed != 0 || st.Failed != 10 {
		t.Fatalf("lost batches must be counted as failed: %+v", st)
	}
}

func TestIDGenMonotonicAndNodeBits(t *testing.T) {
	g := NewIDGen(5)
	prev := uint64(0)
	for i := 0; i < 100_000; i++ {
		id := g.Next()
		if id <= prev {
			t.Fatalf("id %d not greater than previous %d", id, prev)
		}
		if (id>>12)&0x3FF != 5 {
			t.Fatalf("node bits wrong: %x", id)
		}
		prev = id
	}
	// concurrent uniqueness
	var mu sync.Mutex
	seen := map[uint64]bool{}
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20_000; i++ {
				id := g.Next()
				mu.Lock()
				if seen[id] {
					t.Errorf("duplicate id %d", id)
				}
				seen[id] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	// time ordered: an id minted a few ms later sorts after
	a := g.Next()
	time.Sleep(5 * time.Millisecond)
	if b := g.Next(); b <= a {
		t.Fatal("ids must be time-ordered")
	}
}

// The Go structs and the DDL must list the same columns in the same order.
func TestDDLMatchesStructs(t *testing.T) {
	sql, err := chmig.FS.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	cols := ddlColumns(string(sql))
	for table, typ := range map[string]any{"tag_events": TagEvent{}, "flow_events": FlowEvent{}, "finding_events": FindingEvent{}} {
		var want []string
		rt := reflect.TypeOf(typ)
		for i := 0; i < rt.NumField(); i++ {
			want = append(want, rt.Field(i).Tag.Get("ch"))
		}
		if !reflect.DeepEqual(cols[table], want) {
			t.Errorf("%s: DDL columns\n %v\nstruct columns\n %v", table, cols[table], want)
		}
	}
	// request_events mirrors obs.RequestEvent (field order differs in grouping, so compare as sets of names)
	got := strings.Join(cols["request_events"], ",")
	for _, c := range []string{"tenant_id", "session_id", "ts", "event_id", "agent_id", "surface", "method", "stream", "status", "bytes_in", "bytes_out",
		"events_out", "t_authn_us", "t_scan_us", "t_policy_us", "t_rewrite_us", "t_total_added_us", "holdback_p99_us", "n_detect", "n_actions",
		"stage_mask", "degraded", "sink_context_count", "trace_id"} {
		if !strings.Contains(got, c) {
			t.Errorf("request_events DDL lacks %s", c)
		}
	}
	if len(cols["request_events"]) != 24 {
		t.Errorf("request_events has %d columns, the writer sends 24", len(cols["request_events"]))
	}
	// no table may carry a column that could hold a raw value
	for table, cs := range cols {
		for _, c := range cs {
			if strings.Contains(c, "value") || strings.Contains(c, "plaintext") || c == "text" || c == "payload" {
				t.Errorf("%s.%s: lineage tables must never hold raw values", table, c)
			}
		}
	}
}

var tableRE = regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS tw\.(\w+)\s*\((.*?)\)\s*ENGINE`)

func ddlColumns(sql string) map[string][]string {
	out := map[string][]string{}
	for _, m := range tableRE.FindAllStringSubmatch(sql, -1) {
		var cols []string
		depth := 0
		var cur strings.Builder
		flush := func() {
			f := strings.Fields(cur.String())
			if len(f) >= 2 && f[0] != "INDEX" {
				cols = append(cols, f[0])
			}
			cur.Reset()
		}
		for _, line := range strings.Split(m[2], "\n") {
			if i := strings.Index(line, "--"); i >= 0 {
				line = line[:i]
			}
			for _, r := range line {
				switch r {
				case '(':
					depth++
				case ')':
					depth--
				}
				if r == ',' && depth == 0 {
					flush()
					continue
				}
				cur.WriteRune(r)
			}
			cur.WriteByte(' ')
		}
		flush()
		out[m[1]] = cols
	}
	return out
}

func TestSplitStatements(t *testing.T) {
	got := splitStatements("-- c\nCREATE DATABASE IF NOT EXISTS tw;\n\nCREATE TABLE a (\n x UInt8 -- trailing; comment\n) ENGINE = Memory;\n")
	if len(got) != 2 || !strings.HasPrefix(got[0], "CREATE DATABASE") || !strings.Contains(got[1], "x UInt8") || strings.Contains(got[1], "trailing") {
		t.Fatalf("%q", got)
	}
	if n := len(splitStatements(mustRead(t))); n != 5 {
		t.Fatalf("the shipped migration splits into %d statements, want 5 (1 database + 4 tables)", n)
	}
}

func mustRead(t *testing.T) string {
	b, err := chmig.FS.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func BenchmarkEmitNullSink(b *testing.B) {
	p := New(Config{RingSize: 1 << 18, BatchRows: 50_000, FlushEvery: 100 * time.Millisecond, Writers: 2}, &NullSink{})
	defer p.Close()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			e := NewEvent(KindRequest)
			e.Request.AgentID = "a"
			p.Emit(e)
		}
	})
}
