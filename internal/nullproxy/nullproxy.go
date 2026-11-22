// Package nullproxy is the pass-through streaming reverse proxy that defines
// the measurement FLOOR (IMPLEMENTATION_PLAN WP0.4). It has the edge
// configuration the gateway will have (listeners, h1/h2c, flush-per-read,
// per-write deadlines, pooled upstream transport, hop-by-hop hygiene,
// `Accept-Encoding: identity`) and does NO parsing, so everything the real
// gateway later adds above this floor is attributable to inspection.
package nullproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Config configures the proxy.
type Config struct {
	Upstreams     []string      // base URLs; requests round-robin across them (multi-port avoids ephemeral-port exhaustion)
	UpstreamH2C   bool          // speak h2c to upstreams
	WriteDeadline time.Duration // per-flush write deadline (slow-client protection)
	MaxHeader     int
	IdleTimeout   time.Duration
	ReadHeader    time.Duration
}

func (c *Config) defaults() {
	if c.WriteDeadline == 0 {
		c.WriteDeadline = 10 * time.Second
	}
	if c.MaxHeader == 0 {
		c.MaxHeader = 32 << 10
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 120 * time.Second
	}
	if c.ReadHeader == 0 {
		c.ReadHeader = 5 * time.Second
	}
}

// Proxy is the pass-through handler.
type Proxy struct {
	cfg  Config
	ups  []*url.URL
	rr   atomic.Uint64
	rt   http.RoundTripper
	pool sync.Pool

	active   atomic.Int64
	reqs     prometheus.Counter
	reqErrs  *prometheus.CounterVec
	bytesOut prometheus.Counter
	activeG  prometheus.GaugeFunc
}

// New builds a Proxy and registers its metrics on reg (may be nil).
func New(cfg Config, reg prometheus.Registerer) (*Proxy, error) {
	cfg.defaults()
	if len(cfg.Upstreams) == 0 {
		return nil, errors.New("nullproxy: at least one upstream required")
	}
	p := &Proxy{cfg: cfg}
	for _, u := range cfg.Upstreams {
		pu, err := url.Parse(u)
		if err != nil || pu.Scheme != "http" || pu.Host == "" {
			return nil, errors.New("nullproxy: upstream must be http://host:port, got " + u)
		}
		p.ups = append(p.ups, pu)
	}
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	if cfg.UpstreamH2C {
		tr := &http.Transport{
			DialContext: d.DialContext, MaxIdleConnsPerHost: 1 << 20, IdleConnTimeout: 90 * time.Second,
			DisableCompression: true, Protocols: new(http.Protocols),
			HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 1 << 16},
		}
		tr.Protocols.SetUnencryptedHTTP2(true)
		p.rt = tr
	} else {
		p.rt = &http.Transport{
			DialContext: d.DialContext, MaxIdleConns: 0, MaxIdleConnsPerHost: 1 << 20,
			IdleConnTimeout: 90 * time.Second, DisableCompression: true,
			ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
			ReadBufferSize: 16 << 10, WriteBufferSize: 4 << 10,
		}
	}
	p.pool.New = func() any { b := make([]byte, 16<<10); return &b }

	p.reqs = prometheus.NewCounter(prometheus.CounterOpts{Name: "tw_nullproxy_requests_total", Help: "Requests proxied."})
	p.reqErrs = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tw_nullproxy_errors_total", Help: "Upstream or copy errors by kind."}, []string{"kind"})
	p.bytesOut = prometheus.NewCounter(prometheus.CounterOpts{Name: "tw_nullproxy_response_bytes_total", Help: "Response body bytes written to clients."})
	p.activeG = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "tw_streams_active", Help: "In-flight proxied requests."},
		func() float64 { return float64(p.active.Load()) })
	if reg != nil {
		reg.MustRegister(p.reqs, p.reqErrs, p.bytesOut, p.activeG)
	}
	return p, nil
}

var hopByHop = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
}

func copyHeaders(dst, src http.Header) {
	// Headers named in Connection are hop-by-hop too.
	extra := map[string]bool{}
	for _, v := range src.Values("Connection") {
		for _, f := range strings.Split(v, ",") {
			extra[http.CanonicalHeaderKey(strings.TrimSpace(f))] = true
		}
	}
	for k, vs := range src {
		if hopByHop[k] || extra[k] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// ServeHTTP proxies one request, flushing after every upstream read.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.active.Add(1)
	defer p.active.Add(-1)
	p.reqs.Inc()

	// The outbound URL is configured-upstream + request path. Anything that is
	// not a plain origin-form path (absolute-form, authority-form, "*") could
	// steer a naive concatenation to another host: refuse it (ARCHITECTURE §8.3,
	// no open proxy / SSRF).
	if uri := r.URL.RequestURI(); r.URL.IsAbs() || r.URL.Host != "" || len(uri) == 0 || uri[0] != '/' || strings.HasPrefix(uri, "//") {
		http.Error(w, "bad request target", http.StatusBadRequest)
		return
	}
	up := p.ups[(p.rr.Add(1)-1)%uint64(len(p.ups))]
	// Buffer the (bounded) request body, as the gateway will (ADR-05): decisions
	// precede egress. This also decouples the inbound and outbound connections.
	body, rerr := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if rerr != nil {
		http.Error(w, "request body", http.StatusRequestEntityTooLarge)
		return
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, up.String()+r.URL.RequestURI(), bytes.NewReader(body)) //nolint:gosec // G704: host comes from validated config; request target is checked to be an origin-form path above
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	copyHeaders(out.Header, r.Header)
	out.Header.Set("Accept-Encoding", "identity")

	resp, err := p.rt.RoundTrip(out)
	if err != nil {
		p.reqErrs.WithLabelValues("roundtrip").Inc()
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	rc := http.NewResponseController(w)
	_ = rc.Flush() // headers go out on first upstream byte, before any body
	bp := p.pool.Get().(*[]byte)
	defer p.pool.Put(bp)
	buf := *bp
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			_ = rc.SetWriteDeadline(time.Now().Add(p.cfg.WriteDeadline))
			if _, werr := w.Write(buf[:n]); werr != nil {
				p.reqErrs.WithLabelValues("client_write").Inc() // client gone; stop reading upstream (cancels generation)
				return
			}
			if rc.Flush() != nil {
				p.reqErrs.WithLabelValues("client_flush").Inc()
				return
			}
			p.bytesOut.Add(float64(n))
		}
		if rerr != nil {
			if rerr != io.EOF {
				p.reqErrs.WithLabelValues("upstream_read").Inc()
			}
			return
		}
	}
}

// Serve runs the proxy on addr until ctx is cancelled. h2c enables cleartext
// HTTP/2 downstream in addition to HTTP/1.1.
func (p *Proxy) Serve(ctx context.Context, ln net.Listener, h2cEnabled bool, tlsCfg *tls.Config) error {
	srv := &http.Server{
		Handler: p, ReadHeaderTimeout: p.cfg.ReadHeader, IdleTimeout: p.cfg.IdleTimeout,
		MaxHeaderBytes: p.cfg.MaxHeader, TLSConfig: tlsCfg,
	}
	if tlsCfg == nil {
		// Cleartext listener: HTTP/1.1, plus h2c (prior knowledge) when enabled.
		// (With TLS, the default protocol set negotiates h2 via ALPN.)
		srv.Protocols = new(http.Protocols)
		srv.Protocols.SetHTTP1(true)
		srv.Protocols.SetUnencryptedHTTP2(h2cEnabled)
	}
	srv.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: 1 << 16}
	go func() { //nolint:gosec // G118: graceful shutdown deliberately outlives the cancelled serve context
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	var err error
	if tlsCfg != nil {
		err = srv.ServeTLS(ln, "", "")
	} else {
		err = srv.Serve(ln)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
