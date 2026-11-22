package nullproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func startProxy(t *testing.T, upstreams []string, h2cUp bool, h2cDown bool) string {
	t.Helper()
	p, err := New(Config{Upstreams: upstreams, UpstreamH2C: h2cUp}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go p.Serve(ctx, ln, h2cDown, nil)
	return "http://" + ln.Addr().String()
}

// A slow SSE upstream: the proxy must deliver each event as it is produced,
// not buffer the response. This is the property the whole project hangs on.
func TestStreamsWithoutBuffering(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		rc := http.NewResponseController(w)
		for i := 0; i < 4; i++ {
			io.WriteString(w, "data: tick\n\n")
			rc.Flush()
			time.Sleep(60 * time.Millisecond)
		}
	}))
	defer up.Close()
	base := startProxy(t, []string{up.URL}, false, false)

	resp, err := http.Get(base + "/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	t0 := time.Now()
	var arrivals []time.Duration
	for len(arrivals) < 4 {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "data:") {
			arrivals = append(arrivals, time.Since(t0))
		}
	}
	if arrivals[0] > 40*time.Millisecond {
		t.Fatalf("first event after %v; proxy is buffering", arrivals[0])
	}
	if gap := arrivals[3] - arrivals[0]; gap < 150*time.Millisecond {
		t.Fatalf("events arrived in a burst (spread %v); proxy is buffering", gap)
	}
}

func TestHopByHopStrippedAndIdentityEncoding(t *testing.T) {
	var gotEnc, gotConn, gotCustom string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEnc, gotConn, gotCustom = r.Header.Get("Accept-Encoding"), r.Header.Get("X-Hop"), r.Header.Get("X-Keep")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("X-Resp", "yes")
		io.WriteString(w, "body")
	}))
	defer up.Close()
	base := startProxy(t, []string{up.URL}, false, false)
	req, _ := http.NewRequest("GET", base+"/p?q=1", nil)
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "secret")
	req.Header.Set("X-Keep", "v")
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "body" || resp.Header.Get("X-Resp") != "yes" {
		t.Fatalf("response not forwarded: %q %v", b, resp.Header)
	}
	if gotEnc != "identity" {
		t.Fatalf("upstream saw Accept-Encoding %q, want identity", gotEnc)
	}
	if gotConn != "" {
		t.Fatalf("hop-by-hop header listed in Connection leaked upstream: %q", gotConn)
	}
	if gotCustom != "v" {
		t.Fatal("end-to-end header dropped")
	}
}

func TestRoundRobinAcrossUpstreams(t *testing.T) {
	hits := [2]int{}
	var ups []string
	for i := range hits {
		i := i
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits[i]++ }))
		defer s.Close()
		ups = append(ups, s.URL)
	}
	base := startProxy(t, ups, false, false)
	for i := 0; i < 10; i++ {
		resp, err := http.Get(base)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if hits[0] != 5 || hits[1] != 5 {
		t.Fatalf("round robin uneven: %v", hits)
	}
}

func TestUpstreamDownGives502(t *testing.T) {
	base := startProxy(t, []string{"http://127.0.0.1:1"}, false, false)
	resp, err := http.Get(base)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestH2CDownstream(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.Proto) }))
	defer up.Close()
	base := startProxy(t, []string{up.URL}, false, true)
	tr := &http.Transport{Protocols: new(http.Protocols)}
	tr.Protocols.SetUnencryptedHTTP2(true)
	c := &http.Client{Transport: tr}
	resp, err := c.Get(base)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("downstream proto %s, want HTTP/2", resp.Proto)
	}
}

func TestRejectsBadConfig(t *testing.T) {
	if _, err := New(Config{}, nil); err == nil {
		t.Fatal("expected error for no upstreams")
	}
	if _, err := New(Config{Upstreams: []string{"https://x"}}, nil); err == nil {
		t.Fatal("expected error for non-http upstream")
	}
}

// Regression: streaming the INBOUND request body straight into the outbound
// request made the upstream transport close connections mid-response
// ("use of closed network connection"), truncating ~0.5 % of long concurrent
// streams. Found by the load harness's own error accounting; the fix buffers the
// (bounded) request body. This test hammers concurrent POST streams.
func TestConcurrentPostStreamsAreNotTruncated(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		rc := http.NewResponseController(w)
		for i := 0; i < 20; i++ {
			io.WriteString(w, "data: x\n\n")
			rc.Flush()
			time.Sleep(25 * time.Millisecond)
		}
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer up.Close()
	base := startProxy(t, []string{up.URL}, false, false)
	const n = 400
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		go func() {
			resp, err := http.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(`{"stream":true,"padding":"`+strings.Repeat("x", 300)+`"}`))
			if err != nil {
				errs <- err.Error()
				return
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(resp.Body)
			switch {
			case err != nil:
				errs <- err.Error()
			case !strings.HasSuffix(string(b), "data: [DONE]\n\n"):
				errs <- "truncated"
			default:
				errs <- ""
			}
		}()
	}
	bad := 0
	for i := 0; i < n; i++ {
		if e := <-errs; e != "" {
			bad++
			t.Logf("stream failed: %s", e)
		}
	}
	if bad > 0 {
		t.Fatalf("%d of %d concurrent streams were truncated or failed", bad, n)
	}
}

// The proxy must never be steerable to a host other than its configured
// upstreams (no open proxy / SSRF, ARCHITECTURE §8.3): only origin-form targets.
func TestRejectsNonOriginFormTargets(t *testing.T) {
	var hits int
	up := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer up.Close()
	base := startProxy(t, []string{up.URL}, false, false)
	addr := strings.TrimPrefix(base, "http://")
	for _, target := range []string{"http://evil.example/steal", "//evil.example/x", "*"} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(c, "GET "+target+" HTTP/1.1\r\nHost: "+addr+"\r\nConnection: close\r\n\r\n")
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if !strings.Contains(line, "400") {
			t.Errorf("target %q: got %q, want a 400", target, strings.TrimSpace(line))
		}
	}
	if hits != 0 {
		t.Fatalf("%d request(s) reached the upstream for rejected targets", hits)
	}
}
