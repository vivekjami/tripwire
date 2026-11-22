// Package obs is the observability baseline (IMPLEMENTATION_PLAN WP0.6):
// a Prometheus registry, an admin handler (/metrics, pprof, health), a
// field-allow-listed structured logger, and an OpenTelemetry tracer hook that
// is a no-op until an exporter is configured. Metric names and labels defined
// here freeze at the end of Phase 1; dashboards depend on them.
package obs

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/pprof"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// NewRegistry returns a registry with the Go runtime and process collectors,
// which supply process_cpu_seconds_total (used by twload to measure the SUT's
// CPU per request/event) and the go_sched_*/GC metrics used for tail forensics.
func NewRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(collectors.WithGoCollectorRuntimeMetrics(collectors.MetricsAll)),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return reg
}

// AdminHandler serves the admin plane. It MUST be bound to a separate,
// non-public listener (ARCHITECTURE §14.1): pprof and metrics are not data-plane
// endpoints. ready reports readiness; nil means always ready.
func AdminHandler(reg *prometheus.Registry, ready func() bool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{EnableOpenMetrics: true}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if ready != nil && !ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, "ready\n")
	})
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// allowed is the structured-log field allow-list (ARCHITECTURE T14). Anything
// else is dropped, so a stray `slog.String("body", ...)` cannot leak payloads.
var allowed = map[string]bool{
	slog.TimeKey: true, slog.LevelKey: true, slog.MessageKey: true,
	"component": true, "err": true, "addr": true, "listen": true, "target": true, "mode": true,
	"run_id": true, "request_id": true, "trace_id": true, "agent": true, "tenant": true,
	"class": true, "action": true, "rule_id": true, "stage": true, "status": true, "count": true,
	"bytes": true, "dur_ms": true, "version": true, "reason": true, "streams": true, "events": true,
	"go_version": true, "gomaxprocs": true, "nofile": true, "upstreams": true, "path": true,
}

// NewLogger returns a JSON logger that drops every attribute not on the
// allow-list. Payload bytes and detected values are never log fields.
func NewLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && !allowed[a.Key] {
				return slog.Attr{}
			}
			return a
		},
	}))
}

// Tracer returns the named OpenTelemetry tracer. Until a TracerProvider is
// installed with otel.SetTracerProvider, this is a no-op tracer with near-zero
// cost, which is the Phase 0 default.
func Tracer(name string) trace.Tracer { return otel.Tracer(name) }

// StartSpan is a convenience wrapper.
func StartSpan(ctx context.Context, tracer, name string) (context.Context, trace.Span) {
	return Tracer(tracer).Start(ctx, name)
}
