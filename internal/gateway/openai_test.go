package gateway

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vivekjami/tripwire/internal/config"
	"github.com/vivekjami/tripwire/internal/mock"
)

const upstreamCred = "sk-upstream-SECRET-credential"

// recorder is a fake provider that remembers what it was sent.
type recorder struct {
	mu      sync.Mutex
	hits    atomic.Int64
	last    http.Header
	lastURL string
	lastB   []byte
	inner   http.Handler
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.hits.Add(1)
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.last, r.lastURL, r.lastB = req.Header.Clone(), req.URL.Path, b
	r.mu.Unlock()
	req.Body = io.NopCloser(bytes.NewReader(b))
	r.inner.ServeHTTP(w, req)
}

func (r *recorder) snapshot() (http.Header, string, []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last, r.lastURL, r.lastB
}

// startAPI runs a gateway in front of `up` with one route "*" and an upstream credential.
func startAPI(t *testing.T, up http.Handler, mut func(*config.Config)) (*rig, *recorder) {
	t.Helper()
	rec := &recorder{inner: up}
	ts := httptest.NewServer(rec)
	t.Cleanup(ts.Close)
	cf := filepath.Join(t.TempDir(), "cred")
	if err := os.WriteFile(cf, []byte(upstreamCred+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := start(t, func(c *config.Config) {
		c.Upstreams = map[string]config.Upstream{"mock": {URL: ts.URL, CredentialFile: cf, Timeout: 2 * time.Second}}
		c.Routes = []config.Route{{Model: "*", Upstream: "mock"}}
		c.Agents[0].Models = []string{"gpt-*", "o1"}
		if mut != nil {
			mut(c)
		}
	}, nil)
	return r, rec
}

func mockUpstream() http.Handler {
	return mock.New(mock.Config{DefaultGap: "none", DefaultEvents: 8}).Handler()
}

func post(t *testing.T, r *rig, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", r.dataURL+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+r.key)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

const okReq = `{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`

func TestChatNonStreamEndToEnd(t *testing.T) {
	r, rec := startAPI(t, mockUpstream(), nil)
	resp, body := post(t, r, okReq, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, `"chat.completion"`) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Content-Length") != fmt.Sprint(len(body)) {
		t.Fatalf("Content-Length %q for %d-byte body", resp.Header.Get("Content-Length"), len(body))
	}
	if _, path, b := rec.snapshot(); path != "/v1/chat/completions" || string(b) != okReq {
		t.Fatalf("upstream saw %q %q: validated bytes must be forwarded verbatim", path, b)
	}
}

// Differential: through the gateway == direct to the mock, on a corpus, modulo
// fields that are unique per call (id, created).
func TestDifferentialAgainstDirect(t *testing.T) {
	m := mockUpstream()
	direct := httptest.NewServer(m)
	defer direct.Close()
	r, _ := startAPI(t, m, nil)
	corpus := []string{
		okReq,
		`{"model":"gpt-4o","messages":[{"role":"system","content":"s"},{"role":"user","content":"héllo 😀 é"}]}`,
		`{"model":"gpt-4o","temperature":0.2,"max_tokens":50,"messages":[{"role":"user","content":[{"type":"text","text":"parts"}]}]}`,
		`{"model":"gpt-4o","metadata":{"tw_mock":"{\"events\":3,\"stream_id\":\"fixed\"}"},"messages":[{"role":"user","content":"x"}]}`,
		`{"model":"gpt-4o","stream":false,"messages":[{"role":"user","content":"` + strings.Repeat("long ", 2000) + `"}]}`,
	}
	norm := func(b []byte) map[string]any {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("not JSON: %s", b)
		}
		delete(m, "created")
		delete(m, "id")
		return m
	}
	for i, c := range corpus {
		resp, err := http.Post(direct.URL+"/v1/chat/completions", "application/json", strings.NewReader(c))
		if err != nil {
			t.Fatal(err)
		}
		want, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		got, gbody := post(t, r, c, nil)
		if got.StatusCode != resp.StatusCode {
			t.Fatalf("case %d: status %d vs direct %d", i, got.StatusCode, resp.StatusCode)
		}
		if got.StatusCode == 200 {
			wm, gm := norm(want), norm([]byte(gbody))
			// text content is random per mock call unless stream_id/seed fixed: compare shape, not words
			for _, mm := range []map[string]any{wm, gm} {
				delete(mm, "usage")
				for _, ch := range mm["choices"].([]any) {
					ch.(map[string]any)["message"].(map[string]any)["content"] = "-"
				}
			}
			if !reflect.DeepEqual(wm, gm) {
				t.Fatalf("case %d: shape differs\n got %v\nwant %v", i, gm, wm)
			}
		}
	}
}

func TestUpstreamSeesBrokeredCredentialOnly(t *testing.T) {
	r, rec := startAPI(t, mockUpstream(), nil)
	traceOK := "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	resp, _ := post(t, r, okReq, map[string]string{
		"Cookie": "session=abc", "X-Forwarded-For": "6.6.6.6", "Forwarded": "for=6.6.6.6", "Proxy-Authorization": "Basic eA==",
		"X-Api-Key": "agent-secret", "OpenAI-Organization": "org-attacker", "Accept-Encoding": "gzip, br",
		"Traceparent": traceOK, "X-Request-Id": "attacker-chosen", "Connection": "keep-alive, X-Evil", "X-Evil": "1",
		"Te": "trailers", "Upgrade": "websocket",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	h, _, _ := rec.snapshot()
	if got := h.Get("Authorization"); got != "Bearer "+upstreamCred {
		t.Fatalf("upstream Authorization = %q", got)
	}
	for k, vals := range h {
		for _, v := range vals {
			if strings.Contains(v, r.key) {
				t.Errorf("agent credential leaked in header %s", k)
			}
		}
	}
	allowed := map[string]bool{"User-Agent": true, "Accept-Encoding": true, "Content-Type": true, "Accept": true, "X-Request-Id": true,
		"Traceparent": true, "Authorization": true, "Content-Length": true}
	for k := range h {
		if !allowed[k] {
			t.Errorf("unexpected header forwarded upstream: %s: %v", k, h[k])
		}
	}
	if h.Get("Accept-Encoding") != "identity" {
		t.Errorf("Accept-Encoding %q", h.Get("Accept-Encoding"))
	}
	if h.Get("Traceparent") != traceOK {
		t.Errorf("valid traceparent not propagated")
	}
	if h.Get("X-Request-Id") == "attacker-chosen" || !strings.HasPrefix(h.Get("X-Request-Id"), "req_") {
		t.Errorf("request id must be gateway-assigned: %q", h.Get("X-Request-Id"))
	}
	// a malformed traceparent is dropped, not forwarded
	post(t, r, okReq, map[string]string{"Traceparent": "00-ZZZZ51916cd43dd8448eb211c80319c-b7ad6b7169203331-01"})
	post(t, r, okReq, map[string]string{"Traceparent": "garbage"})
	if h, _, _ := rec.snapshot(); h.Get("Traceparent") != "" {
		t.Errorf("malformed traceparent forwarded: %q", h.Get("Traceparent"))
	}
}

func TestUpstreamCredentialNeverReachesClient(t *testing.T) {
	leaky := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "up=1")
		w.Header().Set("X-Debug-Authorization", r.Header.Get("Authorization"))
		w.Header().Set("Server", "evil/1")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`)
	})
	r, _ := startAPI(t, leaky, nil)
	resp, body := post(t, r, okReq, nil)
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, body)
	}
	for k := range resp.Header {
		switch k {
		case "Content-Type", "Content-Length", "X-Request-Id", "Date":
		default:
			t.Errorf("upstream header %s reached the client", k)
		}
	}
}

func rawExchange(t *testing.T, addr, payload string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	_, _ = c.Write([]byte(payload))
	b, _ := io.ReadAll(c)
	return string(b)
}

func TestRequestSmuggling(t *testing.T) {
	r, rec := startAPI(t, mockUpstream(), nil)
	addr := strings.TrimPrefix(r.dataURL, "http://")
	body := okReq
	hdr := "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + r.key + "\r\nContent-Type: application/json\r\n"
	smuggled := "GET /smuggled-" // a second request that must never be executed
	cases := map[string]string{
		"CL+TE (TE wins in some parsers)": hdr + fmt.Sprintf("Content-Length: %d\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n%s HTTP/1.1\r\nHost: x\r\n\r\n", 4, smuggled+"a"),
		"TE+CL":                           hdr + fmt.Sprintf("Transfer-Encoding: chunked\r\nContent-Length: %d\r\n\r\n0\r\n\r\n%s HTTP/1.1\r\nHost: x\r\n\r\n", len(body), smuggled+"b"),
		"duplicate differing CL":          hdr + fmt.Sprintf("Content-Length: %d\r\nContent-Length: 4\r\n\r\n%s", len(body), body+smuggled+"c HTTP/1.1\r\nHost: x\r\n\r\n"),
		"obs-fold header":                 hdr + fmt.Sprintf("Content-Length: %d\r\nX-Folded: a\r\n b\r\n\r\n%s", len(body), body+smuggled+"d HTTP/1.1\r\nHost: x\r\n\r\n"),
		"TE with garbage":                 hdr + "Transfer-Encoding: xchunked\r\n\r\n0\r\n\r\n" + smuggled + "e HTTP/1.1\r\nHost: x\r\n\r\n",
		"TE obfuscated":                   hdr + "Transfer-Encoding : chunked\r\n\r\n0\r\n\r\n" + smuggled + "f HTTP/1.1\r\nHost: x\r\n\r\n",
		"bare LF line endings":            "POST /v1/chat/completions HTTP/1.1\nHost: x\nContent-Length: 0\n\n" + smuggled + "g HTTP/1.1\r\nHost: x\r\n\r\n",
		"space before colon in CL":        hdr + fmt.Sprintf("Content-Length : %d\r\n\r\n%s", len(body), body+smuggled+"h HTTP/1.1\r\nHost: x\r\n\r\n"),
	}
	for name, payload := range cases {
		out := rawExchange(t, addr, payload)
		// A pipelined second request is parsed on its own and must fail
		// authentication; it may never succeed, reach the upstream, or inherit
		// the first request's credentials.
		for _, resp := range strings.Split(out, "HTTP/1.1 ")[1:] {
			code := resp[:3]
			if code == "200" && strings.Contains(resp, "smuggled") {
				t.Errorf("%s: smuggled request succeeded:\n%s", name, out)
			}
		}
		if strings.Count(out, "HTTP/1.1 200") > 1 {
			t.Errorf("%s: more than one successful response on a single connection:\n%s", name, out)
		}
		if _, path, _ := rec.snapshot(); strings.Contains(path, "smuggled") {
			t.Errorf("%s: upstream saw %q", name, path)
		}
	}
}

func TestSmugglingBothCLAndTERejectedBeforeAnyForwarding(t *testing.T) {
	r, rec := startAPI(t, mockUpstream(), nil)
	addr := strings.TrimPrefix(r.dataURL, "http://")
	payload := "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + r.key + "\r\nContent-Type: application/json\r\n" +
		fmt.Sprintf("Content-Length: %d\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(okReq), len(okReq), okReq)
	out := rawExchange(t, addr, payload)
	if rec.hits.Load() != 0 {
		t.Fatalf("a request with both Content-Length and Transfer-Encoding reached the upstream:\n%s", out)
	}
	if !strings.HasPrefix(out, "HTTP/1.1 400") || !strings.Contains(out, "unsupported_transfer_encoding") || !strings.Contains(strings.ToLower(out), "connection: close") {
		t.Fatalf("want 400 + close, got:\n%s", out)
	}
}

func TestStrictJSONRejectionsNeverForwarded(t *testing.T) {
	r, rec := startAPI(t, mockUpstream(), nil)
	for name, body := range map[string]string{
		"duplicate key":      `{"model":"gpt-4o","model":"gpt-4","messages":[{"role":"user","content":"x"}]}`,
		"dup via escape":     `{"model":"gpt-4o","model":"gpt-4","messages":[{"role":"user","content":"x"}]}`,
		"invalid utf-8":      "{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":\"\xff\"}]}",
		"lone surrogate":     `{"model":"gpt-4o","messages":[{"role":"user","content":"\ud83d"}]}`,
		"trailing data":      okReq + ` {"x":1}`,
		"BOM":                "\xef\xbb\xbf" + okReq,
		"deeply nested":      `{"model":"gpt-4o","messages":[{"role":"user","content":"x"}],"x":` + strings.Repeat("[", 70) + strings.Repeat("]", 70) + `}`,
		"bad role":           `{"model":"gpt-4o","messages":[{"role":"admin","content":"x"}]}`,
		"float overflow":     `{"model":"gpt-4o","temperature":1e999,"messages":[{"role":"user","content":"x"}]}`,
		"messages not array": `{"model":"gpt-4o","messages":{}}`,
	} {
		resp, b := post(t, r, body, nil)
		if resp.StatusCode != 400 {
			t.Errorf("%s: status %d %s", name, resp.StatusCode, b)
		}
	}
	if rec.hits.Load() != 0 {
		t.Fatalf("%d rejected requests were forwarded", rec.hits.Load())
	}
}

func TestContentTypeAndMethod(t *testing.T) {
	r, rec := startAPI(t, mockUpstream(), nil)
	for ct, want := range map[string]int{"text/plain": 415, "application/x-www-form-urlencoded": 415, "application/json; charset=latin1": 415, "application/json; charset=utf-8": 200, "application/json": 200} {
		resp, _ := post(t, r, okReq, map[string]string{"Content-Type": ct})
		if resp.StatusCode != want {
			t.Errorf("Content-Type %q: %d want %d", ct, resp.StatusCode, want)
		}
	}
	req, _ := http.NewRequest("GET", r.dataURL+"/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+r.key)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 405 || resp.Header.Get("Allow") != "POST" {
		t.Errorf("GET on chat: %d", resp.StatusCode)
	}
	if rec.hits.Load() != 2 {
		t.Errorf("upstream hits %d, want 2", rec.hits.Load())
	}
}

func TestOversizeAndBomb(t *testing.T) {
	r, rec := startAPI(t, mockUpstream(), func(c *config.Config) { c.Limits.BodyBytes = 64 << 10; c.Limits.DecompressRatio = 20 })
	big := `{"model":"gpt-4o","messages":[{"role":"user","content":"` + strings.Repeat("a", 70<<10) + `"}]}`
	if resp, _ := post(t, r, big, nil); resp.StatusCode != 413 {
		t.Errorf("oversize: %d", resp.StatusCode)
	}
	gz := func(s string) string {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		zw.Write([]byte(s))
		zw.Close()
		return b.String()
	}
	// legitimate gzip body is accepted
	if resp, body := post(t, r, gz(okReq), map[string]string{"Content-Encoding": "gzip"}); resp.StatusCode != 200 {
		t.Errorf("valid gzip: %d %s", resp.StatusCode, body)
	}
	// bomb: tiny compressed, huge decompressed: ratio and size caps
	bomb := `{"model":"gpt-4o","messages":[{"role":"user","content":"` + strings.Repeat("a", 5<<20) + `"}]}`
	cb := gz(bomb)
	if len(cb) > 20<<10 {
		t.Fatalf("test bomb not compact: %d", len(cb))
	}
	if resp, _ := post(t, r, cb, map[string]string{"Content-Encoding": "gzip"}); resp.StatusCode != 413 {
		t.Errorf("gzip bomb: %d", resp.StatusCode)
	}
	// ratio cap alone (decompressed would fit the size cap but exceeds 20x)
	mid := `{"model":"gpt-4o","messages":[{"role":"user","content":"` + strings.Repeat("a", 40<<10) + `"}]}`
	if resp, _ := post(t, r, gz(mid), map[string]string{"Content-Encoding": "gzip"}); resp.StatusCode != 413 {
		t.Errorf("ratio cap: %d (compressed %d bytes)", resp.StatusCode, len(gz(mid)))
	}
	for _, bad := range []string{"br", "deflate", "gzip, gzip", "zstd"} {
		if resp, _ := post(t, r, okReq, map[string]string{"Content-Encoding": bad}); resp.StatusCode != 415 {
			t.Errorf("Content-Encoding %q: %d", bad, resp.StatusCode)
		}
	}
	if resp, _ := post(t, r, "not gzip", map[string]string{"Content-Encoding": "gzip"}); resp.StatusCode != 400 {
		t.Errorf("corrupt gzip: %d", resp.StatusCode)
	}
	if rec.hits.Load() != 1 {
		t.Errorf("only the one valid request may reach the upstream; hits=%d", rec.hits.Load())
	}
}

func TestModelScopeIsIndistinguishableFromNonexistence(t *testing.T) {
	r, rec := startAPI(t, mockUpstream(), nil)
	// agent may use gpt-* and o1; "claude-x" is routed ("*") but not allowed; "o1" ok
	a, abody := post(t, r, `{"model":"claude-x","messages":[{"role":"user","content":"x"}]}`, nil)
	r2, _ := startAPI(t, mockUpstream(), func(c *config.Config) {
		c.Routes = []config.Route{{Model: "only-this", Upstream: "mock"}}
		c.Agents[0].Models = []string{"*"}
	})
	b, bbody := post(t, r2, `{"model":"claude-x","messages":[{"role":"user","content":"x"}]}`, nil)
	if a.StatusCode != 404 || b.StatusCode != 404 || abody != bbody {
		t.Fatalf("scope vs nonexistent differ: %d %q / %d %q", a.StatusCode, abody, b.StatusCode, bbody)
	}
	if rec.hits.Load() != 0 {
		t.Fatal("out-of-scope model reached upstream")
	}
	if resp, _ := post(t, r, `{"model":"o1","messages":[{"role":"user","content":"x"}]}`, nil); resp.StatusCode != 200 {
		t.Fatalf("in-scope model: %d", resp.StatusCode)
	}
}

func TestUpstreamFailureMapping(t *testing.T) {
	type tc struct {
		name   string
		h      http.HandlerFunc
		status int
		code   string
	}
	cases := []tc{
		{"upstream 401 is not the agent's 401", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			io.WriteString(w, `{"error":{"message":"bad key sk-upstream-SECRET"}}`)
		}, 502, "upstream_auth_error"},
		{"non-JSON 200", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "<html>oops</html>") }, 502, "bad_upstream_response"},
		{"malformed JSON 200", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"choices":[`)
		}, 502, "bad_upstream_response"},
		{"duplicate keys in response", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"choices":[],"choices":[]}`)
		}, 502, "bad_upstream_response"},
		{"upstream 429 passes through", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(429)
			io.WriteString(w, `{"error":{"message":"slow down"}}`)
		}, 429, ""},
		{"timeout", func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }, 504, "upstream_timeout"},
	}
	for _, c := range cases {
		r, _ := startAPI(t, c.h, func(cf *config.Config) {
			u := cf.Upstreams["mock"]
			u.Timeout = 300 * time.Millisecond
			cf.Upstreams["mock"] = u
		})
		resp, body := post(t, r, okReq, nil)
		if resp.StatusCode != c.status || (c.code != "" && !strings.Contains(body, c.code)) {
			t.Errorf("%s: %d %s", c.name, resp.StatusCode, body)
		}
		if strings.Contains(body, "SECRET") {
			t.Errorf("%s: upstream secret echoed to client: %s", c.name, body)
		}
		if c.status == 429 && resp.Header.Get("Retry-After") != "7" {
			t.Errorf("%s: Retry-After lost", c.name)
		}
	}
}

func TestResponseTooLarge(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"`+strings.Repeat("a", 200<<10)+`"}}]}`)
	})
	r, _ := startAPI(t, h, func(c *config.Config) { c.Limits.ResponseBytes = 64 << 10 })
	if resp, body := post(t, r, okReq, nil); resp.StatusCode != 502 || !strings.Contains(body, "too_large") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

func TestRetryOnlyWhenNeverSent(t *testing.T) {
	// A dead port: dial fails, nothing was sent, so the retry is safe.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()
	r, _ := startAPI(t, mockUpstream(), func(c *config.Config) {
		c.Upstreams["mock"] = config.Upstream{URL: "http://" + dead, Timeout: time.Second, Retries: 2}
	})
	resp, body := post(t, r, okReq, nil)
	if resp.StatusCode != 502 || !strings.Contains(body, "upstream_unavailable") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	// A server that accepts, reads, then resets: the request MAY have been processed -> no retry.
	var hits atomic.Int64
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			go func() { buf := make([]byte, 4096); _, _ = c.Read(buf); c.Close() }()
		}
	}()
	r2, _ := startAPI(t, mockUpstream(), func(c *config.Config) {
		c.Upstreams["mock"] = config.Upstream{URL: "http://" + ln.Addr().String(), Timeout: time.Second, Retries: 2}
	})
	resp, _ = post(t, r2, okReq, nil)
	if resp.StatusCode != 502 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if hits.Load() != 1 {
		t.Fatalf("a POST that may have been processed was retried: %d connections", hits.Load())
	}
}

func TestModelsListFilteredByAgentScope(t *testing.T) {
	up := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"object":"list","data":[{"id":"gpt-4o","object":"model"},{"id":"gpt-3.5","object":"model"},{"id":"o1","object":"model"},{"id":"claude-x","object":"model"},{"id":"gpt-4o","object":"model"}]}`)
	})
	r, _ := startAPI(t, up, nil)
	req, _ := http.NewRequest("GET", r.dataURL+"/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+r.key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Object string
		Data   []struct{ ID string }
	}
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%s", b)
	}
	var ids []string
	for _, d := range out.Data {
		ids = append(ids, d.ID)
	}
	if !reflect.DeepEqual(ids, []string{"gpt-3.5", "gpt-4o", "o1"}) || out.Object != "list" {
		t.Fatalf("ids %v (agent may use gpt-* and o1; claude-x must be hidden; no duplicates)", ids)
	}
	// every upstream down -> 502, not an empty success
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()
	r2, _ := startAPI(t, up, func(c *config.Config) {
		c.Upstreams["mock"] = config.Upstream{URL: "http://" + dead, Timeout: time.Second}
	})
	req2, _ := http.NewRequest("GET", r2.dataURL+"/v1/models", nil)
	req2.Header.Set("Authorization", "Bearer "+r2.key)
	resp2, _ := http.DefaultClient.Do(req2)
	resp2.Body.Close()
	if resp2.StatusCode != 502 {
		t.Fatalf("all upstreams down: %d", resp2.StatusCode)
	}
}

func TestUnknownRoute(t *testing.T) {
	r, _ := startAPI(t, mockUpstream(), nil)
	req, _ := http.NewRequest("GET", r.dataURL+"/v1/embeddings", nil)
	req.Header.Set("Authorization", "Bearer "+r.key)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
}
