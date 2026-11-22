package obs

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminEndpoints(t *testing.T) {
	ready := false
	ts := httptest.NewServer(AdminHandler(NewRegistry(), func() bool { return ready }))
	defer ts.Close()
	get := func(p string) (int, string) {
		resp, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if c, b := get("/metrics"); c != 200 || !strings.Contains(b, "process_cpu_seconds_total") || !strings.Contains(b, "go_goroutines") {
		t.Fatalf("metrics missing expected series (code %d)", c)
	}
	if c, _ := get("/healthz"); c != 200 {
		t.Fatalf("healthz %d", c)
	}
	if c, _ := get("/readyz"); c != 503 {
		t.Fatalf("readyz while not ready = %d", c)
	}
	ready = true
	if c, _ := get("/readyz"); c != 200 {
		t.Fatalf("readyz while ready = %d", c)
	}
	if c, _ := get("/debug/pprof/cmdline"); c != 200 {
		t.Fatalf("pprof %d", c)
	}
}

func TestLoggerDropsNonAllowListedFields(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, slog.LevelInfo)
	l.Info("hello", "component", "x", "body", "4111 1111 1111 1111", "authorization", "Bearer abc", "count", 3)
	out := buf.String()
	if strings.Contains(out, "4111") || strings.Contains(out, "Bearer") || strings.Contains(out, "body") {
		t.Fatalf("log leaked a non-allow-listed field: %s", out)
	}
	if !strings.Contains(out, `"component":"x"`) || !strings.Contains(out, `"count":3`) {
		t.Fatalf("allow-listed fields missing: %s", out)
	}
}

func TestTracerIsNoopByDefault(t *testing.T) {
	_, span := StartSpan(context.Background(), "test", "op")
	if span.SpanContext().IsValid() {
		t.Fatal("default tracer should be a no-op (invalid span context)")
	}
	span.End()
}

func TestStageTimer(t *testing.T) {
	var now int64
	clk := func() int64 { return now }
	tm := NewStageTimer(clk)
	now += 100_000
	tm.Mark(StageAuthn)
	now += 400_000
	tm.Mark(StageScan)
	now += 50_000
	tm.Mark(StageAuthn) // accumulates
	if tm.DurationUS(StageAuthn) != 150 || tm.DurationUS(StageScan) != 400 || tm.TotalUS() != 550 {
		t.Fatalf("got authn=%d scan=%d total=%d", tm.DurationUS(StageAuthn), tm.DurationUS(StageScan), tm.TotalUS())
	}
}

func TestStageTimerZeroAlloc(t *testing.T) {
	var now int64
	clk := func() int64 { now += 10; return now }
	if n := testing.AllocsPerRun(1000, func() {
		tm := NewStageTimer(clk)
		tm.Mark(StageAuthn)
		tm.Mark(StageScan)
		_ = tm.TotalUS()
	}); n != 0 {
		t.Fatalf("StageTimer allocates: %v allocs/op", n)
	}
}

func TestSurfaceString(t *testing.T) {
	if SurfaceChat.String() != "chat" || SurfaceMCP.String() != "mcp" || Surface(0).String() != "unknown" {
		t.Fatal("surface strings wrong")
	}
}
