// Command twmock is the mock LLM + MCP upstream with ground-truth injection.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/vivekjami/tripwire/internal/groundtruth"
	"github.com/vivekjami/tripwire/internal/mock"
	"github.com/vivekjami/tripwire/internal/obs"
	"github.com/vivekjami/tripwire/internal/sysutil"
)

func main() {
	var (
		listen  = flag.String("listen", "127.0.0.1:9000", "data listener")
		admin   = flag.String("admin", "127.0.0.1:9100", "admin listener (/metrics, pprof); empty disables")
		h2cOn   = flag.Bool("h2c", false, "also accept cleartext HTTP/2")
		events  = flag.Int("events", 64, "default approximate content events per response")
		gap     = flag.String("gap", "const:20ms", "default inter-event gap: none | const:D | lognormal:MEAN,SIGMA | file:PATH")
		chunk   = flag.String("chunk", "token", "default chunking: token | per-char | random:P | boundary | adversarial")
		maxEv   = flag.Int("max-events", 100_000, "hard cap on events per response")
		gtPath  = flag.String("ground-truth", "", "write ground-truth JSONL here")
		emitLog = flag.String("emit-log", "", "write per-event emit timestamps here (CSV)")
		emitSmp = flag.Float64("emit-sample", 1.0, "fraction of streams whose emit timestamps are logged; twload must use the same value")
		mcpVer  = flag.String("mcp-default-version", "2025-11-25", "MCP protocol version assumed when the client sends none")
		hostile = flag.Bool("hostile", false, "MCP hostile mode: poisoned results, rug-pulling tool description")
		hostAft = flag.Int("hostile-after", 2, "tools/list calls before the description mutates")
		gomax   = flag.Int("gomaxprocs", 0, "GOMAXPROCS (0 = leave default)")
	)
	flag.Parse()
	if *gomax > 0 {
		runtime.GOMAXPROCS(*gomax)
	}
	log := obs.NewLogger(os.Stderr, slog.LevelInfo).With("component", "twmock")
	nofile, err := sysutil.RaiseNoFile()
	if err != nil {
		log.Warn("could not raise RLIMIT_NOFILE", "err", err.Error())
	}

	cfg := mock.Config{
		DefaultEvents: *events, DefaultGap: *gap, DefaultChunk: *chunk, MaxEvents: *maxEv,
		EmitSample: *emitSmp, MCPDefaultVersion: *mcpVer, Hostile: *hostile, HostileAfter: *hostAft,
	}
	var closers []func() error
	if *gtPath != "" {
		w, err := groundtruth.NewWriter(*gtPath)
		fatal(log, err)
		cfg.GroundTruth = w
		closers = append(closers, w.Close)
	}
	if *emitLog != "" {
		w, err := groundtruth.NewEmitWriter(*emitLog)
		fatal(log, err)
		cfg.Emit = w
		closers = append(closers, w.Close)
	}
	srv := mock.New(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", *listen)
	fatal(log, err)
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second,
		Protocols: new(http.Protocols), HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 1 << 16}}
	hs.Protocols.SetHTTP1(true)
	hs.Protocols.SetUnencryptedHTTP2(*h2cOn)

	reg := obs.NewRegistry()
	if *admin != "" {
		aln, err := lc.Listen(ctx, "tcp", *admin)
		fatal(log, err)
		go func() {
			adm := &http.Server{Handler: obs.AdminHandler(reg, nil), ReadHeaderTimeout: 5 * time.Second}
			_ = adm.Serve(aln)
		}()
	}

	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	log.Info("listening", "listen", ln.Addr().String(), "go_version", runtime.Version(), "gomaxprocs", runtime.GOMAXPROCS(0), "nofile", nofile)
	if err := hs.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Error("serve", "err", err.Error())
	}
	for _, c := range closers {
		_ = c()
	}
	st := srv.Stats()
	fmt.Fprintf(os.Stderr, "twmock: streams=%d events=%d emit-jitter p50/p99/max=%d/%d/%d µs\n",
		st.StreamsStarted, st.EventsEmitted, st.Jitter.P50, st.Jitter.P99, st.Jitter.Max)
}

func fatal(log *slog.Logger, err error) {
	if err != nil {
		log.Error("fatal", "err", err.Error())
		os.Exit(1)
	}
}
