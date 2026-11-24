package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vivekjami/tripwire/internal/auth"
	"github.com/vivekjami/tripwire/internal/config"
	"github.com/vivekjami/tripwire/internal/lineage"
)

var pepper = []byte("0123456789abcdef-test-pepper")

type rig struct {
	s       *Server
	cancel  context.CancelFunc
	done    chan struct{}
	dataURL string
	admURL  string
	key     string
	dir     string
}

func start(t *testing.T, mut func(*config.Config), routes http.Handler) *rig {
	t.Helper()
	return startSink(t, nil, mut, routes)
}

func startSink(t *testing.T, sink lineage.Sink, mut func(*config.Config), routes http.Handler) *rig {
	t.Helper()
	dir := t.TempDir()
	pf := filepath.Join(dir, "pepper")
	if err := os.WriteFile(pf, pepper, 0o600); err != nil {
		t.Fatal(err)
	}
	key, h, err := auth.GenerateKey("bot", pepper)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Limits.DrainTimeout = 2 * time.Second
	cfg.Auth = config.Auth{PepperFile: pf, APIKeys: []config.APIKey{{Agent: "bot", SHA256: h}}}
	cfg.Agents = []config.Agent{{ID: "bot", Tenant: "t", Models: []string{"*"}}}
	if mut != nil {
		mut(&cfg)
	}
	s, err := New(&cfg, Options{Routes: routes, LineageSink: sink})
	if err != nil {
		t.Fatal(err)
	}
	dl, _ := net.Listen("tcp", "127.0.0.1:0")
	al, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	r := &rig{s: s, cancel: cancel, done: make(chan struct{}), key: key, dir: dir}
	scheme := "http://"
	if cfg.Listen.TLS.CertFile != "" {
		scheme = "https://"
	}
	r.dataURL, r.admURL = scheme+dl.Addr().String(), "http://"+al.Addr().String()
	go func() { _ = s.Serve(ctx, dl, al); close(r.done) }()
	t.Cleanup(func() { cancel(); <-r.done })
	waitReady(t, r.admURL)
	return r
}

func waitReady(t *testing.T, adm string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if resp, err := http.Get(adm + "/readyz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("never ready")
}

func do(t *testing.T, c *http.Client, method, url, bearer string, body io.Reader) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, body)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestAuthFailuresAreUniform(t *testing.T) {
	r := start(t, nil, nil)
	good := r.key
	cases := map[string]string{
		"missing":     "",
		"garbage":     "xyz",
		"wrong tail":  good[:len(good)-1] + "A",
		"unknown":     "tw_ghost_" + strings.Repeat("a", 43),
		"wrong agent": strings.Replace(good, "bot", "bat", 1),
	}
	var first *http.Response
	var firstBody string
	for name, k := range cases {
		resp, body := do(t, http.DefaultClient, "GET", r.dataURL+"/v1/models", k, nil)
		if resp.StatusCode != 401 {
			t.Fatalf("%s: status %d", name, resp.StatusCode)
		}
		resp.Header.Del("X-Request-Id")
		resp.Header.Del("Date")
		if first == nil {
			first, firstBody = resp, body
			continue
		}
		if body != firstBody || resp.Header.Get("WWW-Authenticate") != first.Header.Get("WWW-Authenticate") || resp.Header.Get("Content-Type") != first.Header.Get("Content-Type") {
			t.Errorf("%s differs from the others: %q vs %q", name, body, firstBody)
		}
	}
	// duplicate Authorization headers are ambiguous: rejected even if one is valid
	req, _ := http.NewRequest("GET", r.dataURL+"/v1/models", nil)
	req.Header.Add("Authorization", "Bearer "+good)
	req.Header.Add("Authorization", "Bearer "+good)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("duplicate Authorization accepted: %d", resp.StatusCode)
	}
}

func TestValidKeyReachesRoutesWithoutCredential(t *testing.T) {
	var sawAuth atomic.Value
	var agent, reqID atomic.Value
	routes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth.Store(r.Header.Get("Authorization"))
		agent.Store(AgentFrom(r.Context()).ID)
		reqID.Store(RequestIDFrom(r.Context()))
		io.WriteString(w, "routed")
	})
	r := start(t, nil, routes)
	resp, body := do(t, http.DefaultClient, "GET", r.dataURL+"/x", r.key, nil)
	if resp.StatusCode != 200 || body != "routed" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	if v := sawAuth.Load().(string); v != "" {
		t.Fatalf("inbound Authorization reached the routes: %q", v)
	}
	if agent.Load() != "bot" || !strings.HasPrefix(reqID.Load().(string), "req_") || resp.Header.Get("X-Request-Id") != reqID.Load() {
		t.Fatalf("identity: %v %v %q", agent.Load(), reqID.Load(), resp.Header.Get("X-Request-Id"))
	}
}

func TestDefaultRoutesAreHonestlyNotImplemented(t *testing.T) {
	r := start(t, nil, nil)
	resp, body := do(t, http.DefaultClient, "POST", r.dataURL+"/v1/chat/completions", r.key, strings.NewReader("{}"))
	if resp.StatusCode != 501 || !strings.Contains(body, "not_implemented") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

func TestAdminPlaneIsSeparate(t *testing.T) {
	r := start(t, nil, nil)
	for _, p := range []string{"/metrics", "/debug/pprof/", "/healthz"} {
		// the data listener authenticates first, then hands to routes (501): never the admin handler
		resp, body := do(t, http.DefaultClient, "GET", r.dataURL+p, r.key, nil)
		if resp.StatusCode != 501 || strings.Contains(body, "tw_") {
			t.Errorf("data listener served admin path %s: %d", p, resp.StatusCode)
		}
		resp, _ = do(t, http.DefaultClient, "GET", r.dataURL+p, "", nil)
		if resp.StatusCode != 401 {
			t.Errorf("unauthenticated %s: %d", p, resp.StatusCode)
		}
	}
	resp, body := do(t, http.DefaultClient, "GET", r.admURL+"/metrics", "", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "tw_registry_agents 1") {
		t.Fatalf("admin metrics: %d", resp.StatusCode)
	}
}

func TestPerAgentRateLimit(t *testing.T) {
	r := start(t, func(c *config.Config) { c.Agents[0].Limits = config.AgentLimits{RPS: 5, Burst: 2} }, nil)
	var limited int
	for i := 0; i < 20; i++ {
		resp, _ := do(t, http.DefaultClient, "GET", r.dataURL+"/x", r.key, nil)
		if resp.StatusCode == 429 {
			limited++
			if resp.Header.Get("Retry-After") == "" {
				t.Fatal("429 without Retry-After")
			}
		}
	}
	if limited < 10 {
		t.Fatalf("only %d of 20 limited", limited)
	}
}

func TestGlobalInflightSheds(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{}, 4)
	routes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-gate })
	r := start(t, func(c *config.Config) { c.Limits.GlobalInflight = 2 }, routes)
	for i := 0; i < 2; i++ {
		go func() { _, _ = http.DefaultClient.Do(mustReq(r.dataURL+"/slow", r.key)) }()
	}
	<-entered
	<-entered
	resp, body := do(t, http.DefaultClient, "GET", r.dataURL+"/third", r.key, nil)
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" || !strings.Contains(body, "overloaded") {
		t.Fatalf("third request: %d %s", resp.StatusCode, body)
	}
	close(gate)
}

func mustReq(url, key string) *http.Request {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+key)
	return req
}

func TestPanicFailsClosedAndServerSurvives(t *testing.T) {
	routes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/boom" {
			panic("boom")
		}
		io.WriteString(w, "fine")
	})
	r := start(t, nil, routes)
	resp, body := do(t, http.DefaultClient, "GET", r.dataURL+"/boom", r.key, nil)
	if resp.StatusCode != 500 || strings.Contains(body, "boom") {
		t.Fatalf("%d %q (panic text must not leak)", resp.StatusCode, body)
	}
	if resp, body := do(t, http.DefaultClient, "GET", r.dataURL+"/ok", r.key, nil); resp.StatusCode != 200 || body != "fine" {
		t.Fatal("server did not survive the panic")
	}
}

func TestBodyLimitPerAgent(t *testing.T) {
	routes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(200)
	})
	r := start(t, func(c *config.Config) { c.Agents[0].Limits.MaxBody = 100 }, routes)
	if resp, _ := do(t, http.DefaultClient, "POST", r.dataURL+"/x", r.key, bytes.NewReader(make([]byte, 100))); resp.StatusCode != 200 {
		t.Fatalf("at-limit body: %d", resp.StatusCode)
	}
	if resp, _ := do(t, http.DefaultClient, "POST", r.dataURL+"/x", r.key, bytes.NewReader(make([]byte, 101))); resp.StatusCode != 413 {
		t.Fatalf("over-limit body: %d", resp.StatusCode)
	}
}

func TestHeaderLimit(t *testing.T) {
	r := start(t, func(c *config.Config) { c.Limits.HeaderBytes = 2048 }, nil)
	req := mustReq(r.dataURL+"/x", r.key)
	req.Header.Set("X-Big", strings.Repeat("a", 8192))
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != 431 {
			t.Fatalf("oversize header: %d", resp.StatusCode)
		}
	}
}

func TestStreamCapPerAgent(t *testing.T) {
	r := start(t, func(c *config.Config) { c.Agents[0].Limits.ConcurrentStreams = 2 }, nil)
	a, _ := r.s.reg.Load().Agent("bot")
	rel1, ok1 := r.s.AcquireStream(a)
	rel2, ok2 := r.s.AcquireStream(a)
	_, ok3 := r.s.AcquireStream(a)
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("%v %v %v", ok1, ok2, ok3)
	}
	rel1()
	if _, ok := r.s.AcquireStream(a); !ok {
		t.Fatal("slot not released")
	}
	rel2()
}

func TestGracefulDrain(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{})
	routes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-gate
		io.WriteString(w, "finished")
	})
	r := start(t, nil, routes)
	type res struct {
		body string
		err  error
	}
	out := make(chan res, 1)
	go func() {
		resp, err := http.DefaultClient.Do(mustReq(r.dataURL+"/slow", r.key))
		if err != nil {
			out <- res{err: err}
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		out <- res{body: string(b)}
	}()
	<-entered
	r.cancel() // SIGTERM equivalent
	// readiness must flip while the request is still running
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(r.admURL + "/readyz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 503 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r.s.Ready() {
		t.Fatal("still ready while draining")
	}
	close(gate)
	got := <-out
	if got.err != nil || got.body != "finished" {
		t.Fatalf("in-flight request was not allowed to finish: %+v", got)
	}
	select {
	case <-r.done:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after drain")
	}
}

func TestDrainTimeoutClosesStuckRequests(t *testing.T) {
	entered := make(chan struct{})
	routes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done() // only ends when the connection is closed
	})
	r := start(t, func(c *config.Config) { c.Limits.DrainTimeout = 300 * time.Millisecond }, routes)
	go func() { _, _ = http.DefaultClient.Do(mustReq(r.dataURL+"/stuck", r.key)) }()
	<-entered
	start := time.Now()
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(3 * time.Second):
		t.Fatal("drain did not give up")
	}
	if d := time.Since(start); d < 250*time.Millisecond || d > 2*time.Second {
		t.Fatalf("drain took %v", d)
	}
}

func TestH2CWhenEnabled(t *testing.T) {
	var proto atomic.Value
	routes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proto.Store(r.Proto) })
	r := start(t, func(c *config.Config) { c.Listen.H2C = true }, routes)
	p := new(http.Protocols)
	p.SetUnencryptedHTTP2(true)
	c := &http.Client{Transport: &http.Transport{Protocols: p}}
	do(t, c, "GET", r.dataURL+"/x", r.key, nil)
	if proto.Load() != "HTTP/2.0" {
		t.Fatalf("saw %v", proto.Load())
	}
	// h1 still works on the same port
	do(t, http.DefaultClient, "GET", r.dataURL+"/x", r.key, nil)
	if proto.Load() != "HTTP/1.1" {
		t.Fatalf("saw %v", proto.Load())
	}
}

func TestH2CDisabledByDefault(t *testing.T) {
	r := start(t, nil, nil)
	p := new(http.Protocols)
	p.SetUnencryptedHTTP2(true)
	c := &http.Client{Transport: &http.Transport{Protocols: p}, Timeout: time.Second}
	if resp, err := c.Get(r.dataURL + "/x"); err == nil {
		resp.Body.Close()
		t.Fatalf("h2c prior-knowledge accepted although disabled (status %d)", resp.StatusCode)
	}
}

func TestMaxConnections(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	l := newLimitListener(ln, 2)
	defer l.Close()
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	var dialed []net.Conn
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		dialed = append(dialed, c)
	}
	c1, c2 := <-accepted, <-accepted
	select {
	case <-accepted:
		t.Fatal("third connection accepted over the cap")
	case <-time.After(150 * time.Millisecond):
	}
	c1.Close()
	select {
	case c3 := <-accepted:
		c3.Close()
	case <-time.After(time.Second):
		t.Fatal("slot not released on close")
	}
	c1.Close() // double close must not double-release
	c2.Close()
	for _, c := range dialed {
		c.Close()
	}
}

// ---- TLS hot reload -------------------------------------------------------------

func writePair(t *testing.T, dir, cn string) (certPEM []byte) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	kb, _ := x509.MarshalECPrivateKey(k)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "c.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "k.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPEM
}

func servedCN(t *testing.T, addr string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test reads the presented cert
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].Subject.CommonName
}

func TestTLSHotReloadKeepsGoodCertOnBadReplacement(t *testing.T) {
	cdir := t.TempDir()
	writePair(t, cdir, "first")
	rr := start(t, func(c *config.Config) {
		c.Listen.TLS = config.TLS{CertFile: filepath.Join(cdir, "c.pem"), KeyFile: filepath.Join(cdir, "k.pem")}
	}, nil)
	rr.s.cert.every = 5 * time.Millisecond
	addr := strings.TrimPrefix(rr.dataURL, "https://")
	if cn := servedCN(t, addr); cn != "first" {
		t.Fatalf("cn %q", cn)
	}
	// new valid pair -> picked up
	time.Sleep(20 * time.Millisecond)
	writePair(t, cdir, "second")
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(filepath.Join(cdir, "c.pem"), future, future)
	if cn := servedCN(t, addr); cn != "second" {
		t.Fatalf("reload not picked up: %q", cn)
	}
	// corrupt replacement -> old cert keeps being served
	if err := os.WriteFile(filepath.Join(cdir, "c.pem"), []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	future2 := time.Now().Add(4 * time.Second)
	_ = os.Chtimes(filepath.Join(cdir, "c.pem"), future2, future2)
	time.Sleep(20 * time.Millisecond)
	if cn := servedCN(t, addr); cn != "second" {
		t.Fatalf("bad replacement broke serving: %q", cn)
	}
	// h2 negotiated via ALPN on the TLS listener
	conn, _ := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}}) //nolint:gosec // test
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("ALPN: %q", conn.ConnectionState().NegotiatedProtocol)
	}
}

func TestReloadSwapsRegistryAndKeepsOldOnError(t *testing.T) {
	dir := t.TempDir()
	pf := filepath.Join(dir, "pepper")
	_ = os.WriteFile(pf, pepper, 0o600)
	k1, h1, _ := auth.GenerateKey("bot", pepper)
	k2, h2, _ := auth.GenerateKey("bot", pepper)
	yml := func(hash string) string {
		return "version: \"0.9\"\nauth:\n  pepper_file: " + pf + "\n  api_keys:\n    - {agent: bot, sha256: \"" + hash + "\"}\nagents:\n  - {id: bot, tenant: t, models: [\"*\"]}\n"
	}
	cp := filepath.Join(dir, "tw.yaml")
	_ = os.WriteFile(cp, []byte(yml(h1)), 0o600)
	cfg, err := config.LoadFile(cp)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, Options{ConfigPath: cp})
	if err != nil {
		t.Fatal(err)
	}
	check := func(key string) bool { _, ok := s.reg.Load().Authenticate(key, time.Now()); return ok }
	if !check(k1) || check(k2) {
		t.Fatal("initial state")
	}
	_ = os.WriteFile(cp, []byte(yml(h2)), 0o600)
	if err := s.Reload(); err != nil || check(k1) || !check(k2) {
		t.Fatalf("reload: %v old=%v new=%v", err, check(k1), check(k2))
	}
	_ = os.WriteFile(cp, []byte("version: \"0.9\"\nbogus: 1\n"), 0o600)
	if err := s.Reload(); err == nil || !check(k2) {
		t.Fatalf("a bad file must keep the previous registry (err=%v)", err)
	}
}
