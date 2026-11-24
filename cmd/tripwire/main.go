// Command tripwire is the gateway. Phase 1 (in progress) provides the edge:
// strict config, listeners and limits, TLS hot-reload, authentication,
// admission control, graceful drain and the admin plane. Routes arrive with
// WP1.3; until then authenticated data-plane requests receive 501.
//
//	tripwire -config tripwire.yaml          run
//	tripwire -config tripwire.yaml -check   validate and exit
//	tripwire -print-schema                  print the JSON Schema for the config
//	tripwire genkey -agent ID -pepper-file F   mint an API key (prints key + config hash)
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/vivekjami/tripwire/internal/auth"
	"github.com/vivekjami/tripwire/internal/config"
	"github.com/vivekjami/tripwire/internal/gateway"
	"github.com/vivekjami/tripwire/internal/obs"
	"github.com/vivekjami/tripwire/internal/sysutil"
)

// Version is overridden at link time.
var Version = "0.0.0-phase1"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "genkey" {
		os.Exit(genkey(os.Args[2:]))
	}
	var (
		cfgPath = flag.String("config", "", "path to the YAML config")
		check   = flag.Bool("check", false, "validate the config and exit")
		schema  = flag.Bool("print-schema", false, "print the config JSON Schema and exit")
		debug   = flag.Bool("debug", false, "debug logging")
	)
	flag.Parse()
	if *schema {
		b, err := config.Schema()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(string(b))
		return
	}
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "tripwire: -config is required (see -h)")
		os.Exit(2)
	}
	cfg, err := config.LoadFile(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tripwire: invalid config:")
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *check {
		fmt.Println("config ok")
		return
	}
	lvl := slog.LevelInfo
	if *debug {
		lvl = slog.LevelDebug
	}
	log := obs.NewLogger(os.Stderr, lvl).With("component", "tripwire")
	nofile, _ := sysutil.RaiseNoFile()
	gomax, memlimit := gateway.ApplyRuntime(cfg.Runtime)
	log.Info("runtime", "gomaxprocs", gomax, "nofile", nofile, "bytes", memlimit)

	srv, err := gateway.New(cfg, gateway.Options{ConfigPath: *cfgPath, Log: log, Version: Version})
	if err != nil {
		log.Error("startup", "err", err.Error())
		os.Exit(1)
	}
	var lc net.ListenConfig
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	data, err := lc.Listen(ctx, "tcp", cfg.Listen.Data)
	if err != nil {
		log.Error("listen data", "err", err.Error())
		os.Exit(1)
	}
	admin, err := lc.Listen(ctx, "tcp", cfg.Listen.Admin)
	if err != nil {
		log.Error("listen admin", "err", err.Error())
		os.Exit(1)
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			_ = srv.Reload() // errors are logged and counted; the old registry stays
		}
	}()
	if err := srv.Serve(ctx, data, admin); err != nil {
		log.Error("serve", "err", err.Error())
		os.Exit(1)
	}
}

func genkey(args []string) int {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	agent := fs.String("agent", "", "agent id ([a-z0-9-])")
	pf := fs.String("pepper-file", "", "file containing the pepper (>= 16 bytes)")
	_ = fs.Parse(args)
	pepper, err := auth.ReadPepper(*pf)
	if err != nil || *agent == "" {
		fmt.Fprintln(os.Stderr, "usage: tripwire genkey -agent ID -pepper-file FILE", err)
		return 2
	}
	key, hash, err := auth.GenerateKey(*agent, pepper)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("api key (shown once, give to the agent): %s\nconfig entry:\n  - {agent: %s, sha256: \"%s\"}\n", key, *agent, hash)
	return 0
}
