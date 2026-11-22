// Command twnull is the pass-through "null proxy" that defines the latency and
// CPU floor every later inspection cost is measured against.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/vivekjami/tripwire/internal/nullproxy"
	"github.com/vivekjami/tripwire/internal/obs"
	"github.com/vivekjami/tripwire/internal/sysutil"
)

func main() {
	var (
		listen  = flag.String("listen", "127.0.0.1:9200", "data listener")
		admin   = flag.String("admin", "127.0.0.1:9201", "admin listener (/metrics, pprof)")
		ups     = flag.String("upstream", "http://127.0.0.1:9000", "comma-separated upstream base URLs (round-robin; use several ports to avoid ephemeral-port exhaustion)")
		h2cDown = flag.Bool("h2c", false, "accept cleartext HTTP/2 downstream")
		h2cUp   = flag.Bool("upstream-h2c", false, "speak h2c to upstreams")
		cert    = flag.String("tls-cert", "", "TLS certificate (enables TLS downstream with h2 via ALPN)")
		key     = flag.String("tls-key", "", "TLS key")
		wd      = flag.Duration("write-deadline", 10*time.Second, "per-flush write deadline")
		gomax   = flag.Int("gomaxprocs", 0, "GOMAXPROCS (0 = leave default)")
	)
	flag.Parse()
	if *gomax > 0 {
		runtime.GOMAXPROCS(*gomax)
	}
	log := obs.NewLogger(os.Stderr, slog.LevelInfo).With("component", "twnull")
	nofile, _ := sysutil.RaiseNoFile()

	reg := obs.NewRegistry()
	p, err := nullproxy.New(nullproxy.Config{
		Upstreams: strings.Split(*ups, ","), UpstreamH2C: *h2cUp, WriteDeadline: *wd,
	}, reg)
	if err != nil {
		log.Error("config", "err", err.Error())
		os.Exit(1)
	}
	var tlsCfg *tls.Config
	if *cert != "" {
		c, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			log.Error("tls", "err", err.Error())
			os.Exit(1)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{c}, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", *listen)
	if err != nil {
		log.Error("listen", "err", err.Error())
		os.Exit(1)
	}
	if *admin != "" {
		aln, err := lc.Listen(ctx, "tcp", *admin)
		if err != nil {
			log.Error("admin listen", "err", err.Error())
			os.Exit(1)
		}
		go func() {
			adm := &http.Server{Handler: obs.AdminHandler(reg, nil), ReadHeaderTimeout: 5 * time.Second}
			_ = adm.Serve(aln)
		}()
	}
	log.Info("listening", "listen", ln.Addr().String(), "upstreams", *ups, "go_version", runtime.Version(),
		"gomaxprocs", runtime.GOMAXPROCS(0), "nofile", nofile)
	if err := p.Serve(ctx, ln, *h2cDown, tlsCfg); err != nil {
		log.Error("serve", "err", err.Error())
		os.Exit(1)
	}
}
