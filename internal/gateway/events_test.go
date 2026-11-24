package gateway

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vivekjami/tripwire/internal/config"
	"github.com/vivekjami/tripwire/internal/lineage"
	"github.com/vivekjami/tripwire/internal/obs"
)

func waitEvents(t *testing.T, s *lineage.MemorySink, n int) []lineage.Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := s.Snapshot(); len(got) >= n {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("only %d of %d request events arrived", len(s.Snapshot()), n)
	return nil
}

func TestRequestEventForNonStream(t *testing.T) {
	sink := &lineage.MemorySink{}
	r, _ := startAPISink(t, sink, mockUpstream(), func(c *config.Config) { c.Lineage.FlushInterval = 20 * time.Millisecond })
	tp := "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	resp, body := post(t, r, okReq, map[string]string{"Traceparent": tp})
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, body)
	}
	e := waitEvents(t, sink, 1)[0]
	if e.Kind != lineage.KindRequest {
		t.Fatalf("kind %d", e.Kind)
	}
	q := e.Request
	if q.TenantID != "t" || q.AgentID != "bot" || q.Surface != obs.SurfaceChat || q.Method != "POST" || q.Stream || q.Status != 200 {
		t.Fatalf("%+v", q)
	}
	if q.BytesIn != uint32(len(okReq)) || q.BytesOut != uint32(len(body)) || q.EventsOut != 0 {
		t.Fatalf("sizes: in=%d out=%d (body %d, req %d)", q.BytesIn, q.BytesOut, len(body), len(okReq))
	}
	if hex.EncodeToString(q.TraceID[:]) != "0af7651916cd43dd8448eb211c80319c" {
		t.Fatalf("trace id %x", q.TraceID)
	}
	if q.EventID == 0 || q.TS.IsZero() || time.Since(q.TS) > 5*time.Second {
		t.Fatalf("id/ts: %d %v", q.EventID, q.TS)
	}
	if q.TTotalAddedUS == 0 || q.TTotalAddedUS > 50_000 {
		t.Fatalf("added time %dµs implausible (the mock answers instantly)", q.TTotalAddedUS)
	}
}

func TestRequestEventForStreamCountsEvents(t *testing.T) {
	sink := &lineage.MemorySink{}
	r, _ := startAPISink(t, sink, mockUpstream(), func(c *config.Config) { c.Lineage.FlushInterval = 20 * time.Millisecond })
	body := readAll(streamPost(t, r, streamReq))
	wantEvents := strings.Count(body, "\n\n")
	e := waitEvents(t, sink, 1)[0].Request
	if !e.Stream || e.Status != 200 || int(e.EventsOut) != wantEvents-1 && int(e.EventsOut) != wantEvents { // [DONE] is relayed but may not be counted as a data event
		t.Fatalf("stream event: %+v (client saw %d blocks)", e, wantEvents)
	}
	if e.BytesOut != uint32(len(body)) {
		t.Fatalf("bytes_out %d vs client %d", e.BytesOut, len(body))
	}
	if e.HoldbackP99US > 100_000 {
		t.Fatalf("hold %dµs", e.HoldbackP99US)
	}
}

func TestOnlyAuthenticatedRequestsAreLedgered(t *testing.T) {
	sink := &lineage.MemorySink{}
	r, _ := startAPISink(t, sink, mockUpstream(), func(c *config.Config) { c.Lineage.FlushInterval = 20 * time.Millisecond })
	for i := 0; i < 5; i++ {
		do(t, http.DefaultClient, "GET", r.dataURL+"/v1/models", "bad-key", nil)
	}
	post(t, r, okReq, nil)
	got := waitEvents(t, sink, 1)
	time.Sleep(100 * time.Millisecond)
	if n := len(sink.Snapshot()); n != 1 {
		t.Fatalf("%d events for 5 failed auths + 1 request, want 1: %+v", n, got)
	}
}

func TestEventsNeverContainPayload(t *testing.T) {
	sink := &lineage.MemorySink{}
	r, _ := startAPISink(t, sink, mockUpstream(), func(c *config.Config) { c.Lineage.FlushInterval = 20 * time.Millisecond })
	const secret = "4111 1111 1111 1111 SECRET-MARKER-xyz"
	post(t, r, `{"model":"gpt-4o","messages":[{"role":"user","content":"`+secret+`"}]}`, nil)
	e := waitEvents(t, sink, 1)[0]
	if dump := fmt.Sprintf("%+v", e); strings.Contains(dump, "SECRET-MARKER") || strings.Contains(dump, "4111") {
		t.Fatalf("a request event carries payload: %s", dump)
	}
}

func TestEventIDsAreMonotonicAcrossRequests(t *testing.T) {
	sink := &lineage.MemorySink{}
	r, _ := startAPISink(t, sink, mockUpstream(), func(c *config.Config) { c.Lineage.FlushInterval = 20 * time.Millisecond; c.NodeID = 7 })
	for i := 0; i < 20; i++ {
		post(t, r, okReq, nil)
	}
	evs := waitEvents(t, sink, 20)
	seen := map[uint64]bool{}
	for _, e := range evs {
		id := e.Request.EventID
		if seen[id] || (id>>12)&0x3FF != 7 {
			t.Fatalf("id %x duplicate or wrong node bits", id)
		}
		seen[id] = true
	}
}

func TestServerTimingOnlyForAdminAgents(t *testing.T) {
	r, _ := startAPI(t, mockUpstream(), func(c *config.Config) { c.Agents[0].Admin = false })
	if resp, _ := post(t, r, okReq, nil); resp.Header.Get("Server-Timing") != "" {
		t.Fatalf("Server-Timing leaked to a non-admin agent: %q", resp.Header.Get("Server-Timing"))
	}
	r2, _ := startAPI(t, mockUpstream(), func(c *config.Config) { c.Agents[0].Admin = true })
	resp, _ := post(t, r2, okReq, nil)
	st := resp.Header.Get("Server-Timing")
	for _, part := range []string{"authn;dur=", "scan;dur=", "upstream;dur=", "gateway;dur="} {
		if !strings.Contains(st, part) {
			t.Fatalf("Server-Timing %q lacks %s", st, part)
		}
	}
	sresp := streamPost(t, r2, streamReq)
	sresp.Body.Close()
	if !strings.Contains(sresp.Header.Get("Server-Timing"), "gateway;dur=") {
		t.Fatalf("stream Server-Timing: %q", sresp.Header.Get("Server-Timing"))
	}
}

func TestStuckLineageSinkNeverBlocksRequests(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	r, _ := startAPISink(t, &stuckSink{block}, mockUpstream(), func(c *config.Config) {
		c.Lineage.RingSize = 8
		c.Lineage.BatchRows = 2
		c.Lineage.Writers = 1
	})
	start := time.Now()
	for i := 0; i < 60; i++ {
		if resp, _ := post(t, r, okReq, nil); resp.StatusCode != 200 {
			t.Fatalf("request %d: %d", i, resp.StatusCode)
		}
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("60 requests took %v with a stuck lineage sink: the data path is blocked on observability", d)
	}
	if st := r.s.lin.Stats(); st.Dropped == 0 {
		t.Fatalf("a full ring must drop and count, not block: %+v", st)
	}
}

type stuckSink struct{ block chan struct{} }

func (s *stuckSink) WriteBatch(_ context.Context, _ []*lineage.Event) error { <-s.block; return nil }
func (s *stuckSink) Close() error                                           { return nil }
