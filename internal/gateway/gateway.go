// Package gateway is the data-plane edge: listeners and their limits, TLS,
// graceful drain, the admin plane, request identity, authentication and
// admission control. Routing and inspection plug in through Options.Routes.
//
// Middleware order (outermost first): panic recovery -> request id -> global
// in-flight shedding -> authentication -> per-agent rate limit -> body limit
// -> routes. Failure semantics are explicit: panics and unexpected errors fail
// closed (500, never a forwarded request).
package gateway

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/ch-go"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/vivekjami/tripwire/internal/auth"
	"github.com/vivekjami/tripwire/internal/config"
	"github.com/vivekjami/tripwire/internal/lineage"
	"github.com/vivekjami/tripwire/internal/obs"
)

type ctxKey int

const (
	agentKey ctxKey = iota
	reqIDKey
)

// AgentFrom returns the authenticated agent of a request.
func AgentFrom(ctx context.Context) *auth.Agent { a, _ := ctx.Value(agentKey).(*auth.Agent); return a }

// RequestIDFrom returns the gateway-assigned request id.
func RequestIDFrom(ctx context.Context) string { s, _ := ctx.Value(reqIDKey).(string); return s }

// Options plugs the rest of the gateway into the edge.
type Options struct {
	ConfigPath string       // for Reload; may be empty in tests
	Routes     http.Handler // data-plane routes behind authentication; nil = 501 for everything
	Log        *slog.Logger
	Metrics    *prometheus.Registry
	Version    string
	// LineageSink overrides the configured sink (tests, embedding).
	LineageSink lineage.Sink
}

// Server is the edge.
type Server struct {
	cfg  *config.Config
	opt  Options
	log  *slog.Logger
	reg  auth.Holder
	m    *metrics
	cert *certReloader

	inflight *auth.Gate
	lin      *lineage.Pipeline
	ids      *lineage.IDGen
	ready    atomic.Bool
	draining atomic.Bool
}

type metrics struct {
	requests    *prometheus.CounterVec
	inflight    prometheus.Gauge
	shed        *prometheus.CounterVec
	authFail    prometheus.Counter
	panics      prometheus.Counter
	tlsReload   *prometheus.CounterVec
	regReload   *prometheus.CounterVec
	regAgents   prometheus.Gauge
	reqDuration prometheus.Histogram
}

func newMetrics(r *prometheus.Registry) *metrics {
	m := &metrics{
		requests:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tw_http_requests_total", Help: "Data-plane requests by status class."}, []string{"class"}),
		inflight:  prometheus.NewGauge(prometheus.GaugeOpts{Name: "tw_inflight_requests", Help: "Requests currently being served."}),
		shed:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tw_shed_total", Help: "Requests rejected by admission control."}, []string{"reason"}),
		authFail:  prometheus.NewCounter(prometheus.CounterOpts{Name: "tw_auth_failures_total", Help: "Rejected authentications (reason is deliberately not exposed)."}),
		panics:    prometheus.NewCounter(prometheus.CounterOpts{Name: "tw_panics_total", Help: "Recovered handler panics (failed closed)."}),
		tlsReload: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tw_tls_reload_total", Help: "TLS certificate reload attempts."}, []string{"result"}),
		regReload: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tw_registry_reload_total", Help: "Agent registry reload attempts."}, []string{"result"}),
		regAgents: prometheus.NewGauge(prometheus.GaugeOpts{Name: "tw_registry_agents", Help: "Agents in the current registry snapshot."}),
		reqDuration: prometheus.NewHistogram(prometheus.HistogramOpts{Name: "tw_http_request_seconds", Help: "Total request duration.",
			NativeHistogramBucketFactor: 1.1, NativeHistogramMaxBucketNumber: 100, Buckets: prometheus.ExponentialBuckets(0.0005, 2, 16)}),
	}
	r.MustRegister(m.requests, m.inflight, m.shed, m.authFail, m.panics, m.tlsReload, m.regReload, m.regAgents, m.reqDuration)
	return m
}

// New builds a server from validated config.
func New(cfg *config.Config, opt Options) (*Server, error) {
	if opt.Log == nil {
		opt.Log = slog.New(slog.DiscardHandler)
	}
	if opt.Metrics == nil {
		opt.Metrics = obs.NewRegistry()
	}
	s := &Server{cfg: cfg, opt: opt, log: opt.Log, m: newMetrics(opt.Metrics), inflight: auth.NewGate(cfg.Limits.GlobalInflight)}
	if opt.Routes == nil {
		if len(cfg.Routes) > 0 {
			api, err := s.newChatAPI()
			if err != nil {
				return nil, err
			}
			s.opt.Routes = api.Handler()
		} else {
			s.opt.Routes = http.HandlerFunc(notImplemented)
		}
	}
	pepper, err := auth.ReadPepper(cfg.Auth.PepperFile)
	if err != nil {
		return nil, err
	}
	r, err := auth.Build(cfg, pepper, nil)
	if err != nil {
		return nil, err
	}
	s.reg.Store(r)
	s.m.regAgents.Set(float64(r.Len()))
	if err := s.startLineage(); err != nil {
		return nil, err
	}
	if cfg.Listen.TLS.CertFile != "" {
		s.cert, err = newCertReloader(cfg.Listen.TLS.CertFile, cfg.Listen.TLS.KeyFile, func(ok bool) {
			res := "ok"
			if !ok {
				res = "error"
				s.log.Error("tls reload failed; keeping previous certificate")
			}
			s.m.tlsReload.WithLabelValues(res).Inc()
		})
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Reload re-reads the config file and swaps the agent registry (agents, keys,
// limits). Listener, TLS-path and runtime settings need a restart; a change to
// them is logged, not silently ignored. A bad file leaves the old registry.
func (s *Server) Reload() error {
	if s.opt.ConfigPath == "" {
		return errors.New("gateway: no config path to reload")
	}
	nc, err := config.LoadFile(s.opt.ConfigPath)
	if err == nil {
		var pepper []byte
		if pepper, err = auth.ReadPepper(nc.Auth.PepperFile); err == nil {
			var r *auth.Registry
			if r, err = auth.Build(nc, pepper, s.reg.Load()); err == nil {
				s.reg.Store(r)
				s.m.regAgents.Set(float64(r.Len()))
				s.m.regReload.WithLabelValues("ok").Inc()
				if nc.Listen != s.cfg.Listen || nc.Limits != s.cfg.Limits || nc.Runtime != s.cfg.Runtime ||
					!reflect.DeepEqual(nc.Upstreams, s.cfg.Upstreams) || !reflect.DeepEqual(nc.Routes, s.cfg.Routes) ||
					!reflect.DeepEqual(nc.Lineage, s.cfg.Lineage) || nc.NodeID != s.cfg.NodeID {
					s.log.Warn("listener, limit, runtime, upstream or route settings changed; they apply only after a restart", "reason", "restart_required")
				}
				s.log.Info("registry reloaded", "count", r.Len())
				return nil
			}
		}
	}
	s.m.regReload.WithLabelValues("error").Inc()
	s.log.Error("reload failed; keeping previous registry", "err", err.Error())
	return err
}

// Handler returns the data-plane handler (exported for tests and embedding).
func (s *Server) Handler() http.Handler {
	return s.recoverMW(s.requestIDMW(s.framingMW(s.shedMW(s.authMW(s.limitMW(s.opt.Routes))))))
}

// Ready reports readiness: listeners up and not draining.
func (s *Server) Ready() bool { return s.ready.Load() && !s.draining.Load() }

// Serve runs both listeners until ctx is cancelled, then drains. It returns
// after the drain completes (or drain_timeout expires).
func (s *Server) Serve(ctx context.Context, data, admin net.Listener) error {
	l := s.cfg.Limits
	if l.MaxConnections > 0 {
		data = newLimitListener(data, l.MaxConnections)
	}
	srv := &http.Server{
		Handler: s.Handler(), ReadHeaderTimeout: l.ReadHeaderTimeout, IdleTimeout: l.IdleTimeout, MaxHeaderBytes: l.HeaderBytes,
		HTTP2:    &http.HTTP2Config{MaxConcurrentStreams: 1000},
		ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	tlsOn := s.cert != nil
	if tlsOn {
		srv.TLSConfig = &tls.Config{GetCertificate: s.cert.GetCertificate, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
		if ca := s.cfg.Listen.TLS.ClientCAFile; ca != "" {
			pem, err := os.ReadFile(ca) //nolint:gosec // operator-supplied path
			pool := x509.NewCertPool()
			if err != nil || !pool.AppendCertsFromPEM(pem) {
				return errors.New("gateway: client_ca_file unreadable or empty")
			}
			// Optional mTLS: a certificate is not required, but one that is
			// presented must chain to this CA (an unverifiable cert fails the handshake).
			srv.TLSConfig.ClientCAs, srv.TLSConfig.ClientAuth = pool, tls.VerifyClientCertIfGiven
		}
	} else {
		srv.Protocols = new(http.Protocols)
		srv.Protocols.SetHTTP1(true)
		srv.Protocols.SetUnencryptedHTTP2(s.cfg.Listen.H2C)
	}
	adm := &http.Server{Handler: obs.AdminHandler(s.opt.Metrics, s.Ready), ReadHeaderTimeout: 5 * time.Second}

	errc := make(chan error, 2)
	go func() {
		if tlsOn {
			errc <- srv.ServeTLS(data, "", "")
		} else {
			errc <- srv.Serve(data)
		}
	}()
	go func() { errc <- adm.Serve(admin) }()
	s.ready.Store(true)
	s.banner(data.Addr().String(), admin.Addr().String(), tlsOn)

	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	// Drain: fail readiness first so load balancers stop sending, then let
	// in-flight requests (including streams) finish within drain_timeout.
	s.draining.Store(true)
	s.log.Info("draining", "dur_ms", l.DrainTimeout.Milliseconds())
	dctx, cancel := context.WithTimeout(context.Background(), l.DrainTimeout)
	defer cancel()
	if serr := srv.Shutdown(dctx); serr != nil {
		s.log.Warn("drain timeout; closing remaining connections", "err", serr.Error())
		_ = srv.Close()
	}
	_ = adm.Shutdown(dctx)
	_ = s.lin.Close() // flush queued request events before exiting
	return err
}

func (s *Server) banner(data, admin string, tlsOn bool) {
	rev := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, kv := range bi.Settings {
			if kv.Key == "vcs.revision" && len(kv.Value) >= 7 {
				rev = kv.Value[:7]
			}
		}
	}
	mode := "h1"
	switch {
	case tlsOn:
		mode = "tls(h1,h2)"
	case s.cfg.Listen.H2C:
		mode = "h1+h2c"
	}
	s.log.Info("tripwire started", "version", s.opt.Version+"+"+rev, "go_version", runtime.Version(), "gomaxprocs", runtime.GOMAXPROCS(0),
		"listen", data, "addr", admin, "mode", mode, "count", s.reg.Load().Len())
}

// ---- middleware --------------------------------------------------------------

func (s *Server) recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler { //nolint:errorlint // sentinel compared by identity per net/http docs
					panic(v)
				}
				s.m.panics.Inc()
				s.log.Error("handler panic; failing closed", "reason", "panic", "path", r.URL.Path)
				writeErr(w, http.StatusInternalServerError, "server_error", "internal_error", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	code  int
	bytes uint32
}

func (w *statusWriter) WriteHeader(c int) {
	if w.code == 0 {
		w.code = c
	}
	w.ResponseWriter.WriteHeader(c)
}
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += uint32(n)
	return n, err
}

// Unwrap lets http.ResponseController reach Flush/SetWriteDeadline.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) requestIDMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		var b [8]byte
		_, _ = rand.Read(b[:])
		id := "req_" + hex.EncodeToString(b[:])
		w.Header().Set("X-Request-Id", id)
		sw := &statusWriter{ResponseWriter: w}
		st := newReqState()
		st.method = r.Method
		ctx := context.WithValue(context.WithValue(r.Context(), reqIDKey, id), reqStateKey, st)
		next.ServeHTTP(sw, r.WithContext(ctx))
		code := sw.code
		if code == 0 {
			code = http.StatusOK
		}
		s.m.requests.WithLabelValues(strconv.Itoa(code/100) + "xx").Inc()
		s.m.reqDuration.Observe(time.Since(start).Seconds())
		s.emit(st, code, sw.bytes, r.Header.Get("Traceparent"))
	})
}

// framingMW closes the HTTP/1 request-smuggling class (ARCHITECTURE §12.5).
// Go's parser accepts "Transfer-Encoding: chunked" together with a
// Content-Length (chunked wins and the Content-Length header is deleted before
// handlers run, so the combination cannot be observed here). Rather than trust
// every other hop to resolve that ambiguity the same way, the data plane
// refuses Transfer-Encoding altogether: API clients send a Content-Length for
// JSON bodies. The connection is closed so no leftover bytes are re-parsed.
func (s *Server) framingMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TransferEncoding) > 0 || r.Header.Get("Transfer-Encoding") != "" {
			s.m.shed.WithLabelValues("framing").Inc()
			w.Header().Set("Connection", "close")
			writeErr(w, http.StatusBadRequest, "invalid_request_error", "unsupported_transfer_encoding", "Transfer-Encoding is not supported; send Content-Length")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// shedMW enforces the global in-flight cap: overload is answered with 429 +
// Retry-After instead of queueing (ARCHITECTURE §8.5).
func (s *Server) shedMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.inflight.TryAcquire() {
			s.m.shed.WithLabelValues("global_inflight").Inc()
			w.Header().Set("Retry-After", "1")
			writeErr(w, http.StatusTooManyRequests, "rate_limit_error", "overloaded", "server is at capacity; retry shortly")
			return
		}
		s.m.inflight.Inc()
		defer func() { s.inflight.Release(); s.m.inflight.Dec() }()
		next.ServeHTTP(w, r)
	})
}

// authMW authenticates the caller: "Authorization: Bearer <api key or JWT>"
// and/or a verified client certificate. If both are presented they must name the
// same agent. Every failure mode returns the same status, headers and body
// (no oracle).
func (s *Server) authMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reg := s.reg.Load()
		now := time.Now()
		var a *auth.Agent
		ok := true
		hdrs := r.Header.Values("Authorization")
		hasBearer := len(hdrs) > 0
		if hasBearer {
			tok, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if len(hdrs) != 1 || !found { // duplicates are ambiguous; other schemes are unsupported
				tok = ""
			}
			a, ok = reg.AuthenticateBearer(r.Context(), tok, now)
		}
		if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.PeerCertificates) > 0 {
			var uris []string
			for _, u := range r.TLS.PeerCertificates[0].URIs {
				uris = append(uris, u.String())
			}
			ca, cok := reg.AuthenticateCert(uris)
			switch {
			case !hasBearer:
				a, ok = ca, cok
			case ok && (!cok || ca.ID != a.ID): // two identities that disagree
				ok = false
			}
		} else if !hasBearer {
			ok = false
		}
		if !ok || a == nil {
			s.m.authFail.Inc()
			w.Header().Set("WWW-Authenticate", `Bearer realm="tripwire"`)
			writeErr(w, http.StatusUnauthorized, "invalid_request_error", "invalid_api_key", "invalid authentication")
			return
		}
		// The inbound credential is consumed here; it is removed so no later
		// stage can forward it upstream (ARCHITECTURE §8.3, T10).
		r.Header.Del("Authorization")
		if st := stateFrom(r.Context()); st != nil {
			st.agent = a
			st.timer.Mark(obs.StageAuthn)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), agentKey, a)))
	})
}

// limitMW applies the per-agent rate limit and the request-body cap.
func (s *Server) limitMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := AgentFrom(r.Context())
		if ok, retry := a.Rate.Allow(time.Now().UnixNano()); !ok {
			s.m.shed.WithLabelValues("agent_rate").Inc()
			secs := int(retry/time.Second) + 1
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			writeErr(w, http.StatusTooManyRequests, "rate_limit_error", "rate_limit_exceeded", "rate limit exceeded")
			return
		}
		max := s.cfg.Limits.BodyBytes
		if a.MaxBody > 0 && a.MaxBody < max {
			max = a.MaxBody
		}
		r.Body = http.MaxBytesReader(w, r.Body, max)
		next.ServeHTTP(w, r)
	})
}

// AcquireStream takes a concurrent-stream slot for the agent; the returned
// func releases it. ok=false means the agent's cap is reached (answer 429).
func (s *Server) AcquireStream(a *auth.Agent) (release func(), ok bool) {
	if !a.Streams.TryAcquire() {
		s.m.shed.WithLabelValues("stream_cap").Inc()
		return nil, false
	}
	return a.Streams.Release, true
}

func notImplemented(w http.ResponseWriter, _ *http.Request) {
	writeErr(w, http.StatusNotImplemented, "server_error", "not_implemented", "this route is not implemented yet")
}

// writeErr writes an OpenAI-shaped error body.
func writeErr(w http.ResponseWriter, status int, typ, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":{"message":` + strconv.Quote(msg) + `,"type":"` + typ + `","code":"` + code + `"}}` + "\n"))
}

// ---- connection cap ----------------------------------------------------------

type limitListener struct {
	net.Listener
	sem chan struct{}
}

func newLimitListener(l net.Listener, n int) net.Listener {
	return &limitListener{Listener: l, sem: make(chan struct{}, n)}
}

func (l *limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{} // blocks accepting while at the cap; the kernel backlog absorbs the rest
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

type limitConn struct {
	net.Conn
	release func()
	done    atomic.Bool
}

func (c *limitConn) Close() error {
	if c.done.CompareAndSwap(false, true) {
		c.release()
	}
	return c.Conn.Close()
}

// ApplyRuntime sets GOMAXPROCS and the soft memory limit from config. It
// returns what it applied for the banner.
func ApplyRuntime(rt config.Runtime) (gomaxprocs int, memLimit int64) {
	if rt.GOMAXPROCS > 0 {
		runtime.GOMAXPROCS(rt.GOMAXPROCS)
	}
	if rt.MemLimit != "" {
		if n, err := config.ParseBytes(rt.MemLimit); err == nil {
			debug.SetMemoryLimit(n)
			memLimit = n
		}
	} else if v := os.Getenv("GOMEMLIMIT"); v != "" {
		memLimit = debug.SetMemoryLimit(-1)
	}
	return runtime.GOMAXPROCS(0), memLimit
}

// startLineage builds the request-event pipeline from config (or the override).
func (s *Server) startLineage() error {
	lc := s.cfg.Lineage
	sink := s.opt.LineageSink
	if sink == nil {
		switch lc.Sink {
		case "clickhouse":
			pw, err := auth.ReadPepper(lc.ClickHouse.PasswordFile) // same trimmed-file reader
			if err != nil {
				return err
			}
			comp := ch.CompressionDisabled
			if lc.ClickHouse.Compression == "lz4" {
				comp = ch.CompressionLZ4
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cs, err := lineage.NewCHSink(ctx, lineage.CHConfig{Addr: lc.ClickHouse.Addr, User: lc.ClickHouse.User, Password: string(pw),
				Compression: comp, Node: strconv.Itoa(s.cfg.NodeID)})
			if err != nil {
				return fmt.Errorf("gateway: lineage clickhouse: %w", err)
			}
			sink = cs
		default:
			sink = &lineage.NullSink{}
		}
	}
	s.ids = lineage.NewIDGen(uint16(s.cfg.NodeID))
	s.lin = lineage.New(lineage.Config{RingSize: lc.RingSize, BatchRows: lc.BatchRows, FlushEvery: lc.FlushInterval, Writers: lc.Writers,
		Registry: s.opt.Metrics}, sink)
	return nil
}
