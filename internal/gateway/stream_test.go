package gateway

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vivekjami/tripwire/internal/config"
)

const streamReq = `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hello"}]}`

// chunkRaw puts content into the JSON verbatim (it must already be JSON-escaped).
func chunkRaw(content string) string {
	return `{"id":"c1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"` + content + `"}}]}`
}

func chunkJSON(i int, content string) string {
	return fmt.Sprintf(`{"id":"c1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":%q}}]}`, content)
}

// sseUpstream writes the given raw pieces (with optional delays) as an SSE response.
func sseUpstream(pieces []string, gap time.Duration, cancelled *atomic.Bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fl := w.(http.Flusher)
		for _, p := range pieces {
			select {
			case <-r.Context().Done():
				if cancelled != nil {
					cancelled.Store(true)
				}
				return
			default:
			}
			io.WriteString(w, p)
			fl.Flush()
			if gap > 0 {
				select {
				case <-time.After(gap):
				case <-r.Context().Done():
					if cancelled != nil {
						cancelled.Store(true)
					}
					return
				}
			}
		}
	})
}

func streamPost(t *testing.T, r *rig, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", r.dataURL+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+r.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readAll(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestStreamEndToEndWithMock(t *testing.T) {
	r, _ := startAPI(t, mockUpstream(), nil)
	resp := streamPost(t, r, streamReq)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	if resp.Header.Get("Content-Length") != "" || resp.Header.Get("X-Accel-Buffering") != "no" || resp.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("headers %v", resp.Header)
	}
	body := readAll(resp)
	if strings.Count(body, "data: {") < 5 || !strings.HasSuffix(body, "data: [DONE]\n\n") {
		t.Fatalf("unexpected stream:\n%.400s", body)
	}
}

// Whatever the upstream wrote, byte for byte, is what the client receives.
func TestStreamForwardsEventsVerbatim(t *testing.T) {
	pieces := []string{
		": keep-alive comment\n\n",
		"data: " + chunkJSON(0, "Hel") + "\r\n\r\n", // CRLF framing
		"event: delta\nid: 42\ndata: " + chunkJSON(1, "lo") + "\n\n",
		"data:" + chunkJSON(2, " wörld 😀") + "\n\n",                                  // no space after colon
		"data: {\"choices\":[{\"delta\":\n" + "data: {\"content\":\"multi\"}}]}\n\n", // JSON split across data lines (joined with \n)
		"data: " + chunkRaw(`\ud83d`) + "\n\n",                                       // lone surrogate (pair split across events)
		"data: " + chunkRaw(`\ude00`) + "\n\n",
		"data: [DONE]\n\n",
	}
	want := strings.Join(pieces, "")
	r, _ := startAPI(t, sseUpstream(pieces, 0, nil), nil)
	got := readAll(streamPost(t, r, streamReq))
	if got != want {
		t.Fatalf("stream was altered:\n got %q\nwant %q", got, want)
	}
}

func TestStreamFlushesEachEventWithoutBuffering(t *testing.T) {
	const n, gap = 5, 80 * time.Millisecond
	pieces := make([]string, 0, n+1)
	for i := 0; i < n; i++ {
		pieces = append(pieces, "data: "+chunkJSON(i, "x")+"\n\n")
	}
	pieces = append(pieces, "data: [DONE]\n\n")
	r, _ := startAPI(t, sseUpstream(pieces, gap, nil), nil)
	resp := streamPost(t, r, streamReq)
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	var at []time.Time
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "data: {") {
			at = append(at, time.Now())
		}
	}
	if len(at) != n {
		t.Fatalf("%d events", len(at))
	}
	for i := 1; i < n; i++ {
		if d := at[i].Sub(at[i-1]); d < gap/2 {
			t.Errorf("events %d and %d arrived %v apart: the gateway is batching (upstream gap %v)", i-1, i, d, gap)
		}
	}
}

func TestStreamMalformedUpstreamEventTerminatesWithErrorEvent(t *testing.T) {
	for name, bad := range map[string]string{
		"not json":      "data: this is not json\n\n",
		"duplicate key": `data: {"choices":[{"delta":{"content":"a","content":"b"}}]}` + "\n\n",
		"invalid utf8":  "data: {\"choices\":[{\"delta\":{\"content\":\"\xff\"}}]}\n\n",
	} {
		var cancelled atomic.Bool
		pieces := []string{"data: " + chunkJSON(0, "ok") + "\n\n", bad, "data: " + chunkJSON(2, "must-not-arrive") + "\n\n", "data: [DONE]\n\n"}
		r, _ := startAPI(t, sseUpstream(pieces, 30*time.Millisecond, &cancelled), nil)
		got := readAll(streamPost(t, r, streamReq))
		if !strings.Contains(got, `"ok"`) || strings.Contains(got, "must-not-arrive") || strings.Contains(got, "this is not json") {
			t.Errorf("%s: bad event leaked or good event lost:\n%s", name, got)
		}
		if !strings.Contains(got, "bad_upstream_event") || !strings.HasSuffix(got, "data: [DONE]\n\n") {
			t.Errorf("%s: missing error event / terminator:\n%s", name, got)
		}
		time.Sleep(150 * time.Millisecond)
		if !cancelled.Load() {
			t.Errorf("%s: upstream was not cancelled", name)
		}
	}
}

func TestStreamUpstreamDiesMidStreamAndStalls(t *testing.T) {
	// ends without [DONE]
	r, _ := startAPI(t, sseUpstream([]string{"data: " + chunkJSON(0, "a") + "\n\n"}, 0, nil), nil)
	got := readAll(streamPost(t, r, streamReq))
	if !strings.Contains(got, "upstream_incomplete") || !strings.HasSuffix(got, "data: [DONE]\n\n") {
		t.Fatalf("no-DONE stream:\n%s", got)
	}
	// dies inside an event
	r, _ = startAPI(t, sseUpstream([]string{"data: " + chunkJSON(0, "a") + "\n\n", "data: {\"par"}, 0, nil), nil)
	if got := readAll(streamPost(t, r, streamReq)); !strings.Contains(got, "upstream_incomplete") && !strings.Contains(got, "upstream_error") {
		t.Fatalf("truncated event:\n%s", got)
	}
	// stalls forever after one event
	var cancelled atomic.Bool
	h := http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: "+chunkJSON(0, "a")+"\n\n")
		w.(http.Flusher).Flush()
		<-rq.Context().Done()
		cancelled.Store(true)
	})
	r, _ = startAPI(t, h, func(c *config.Config) { c.Limits.StreamIdle = 300 * time.Millisecond })
	start := time.Now()
	got = readAll(streamPost(t, r, streamReq))
	if !strings.Contains(got, "upstream_stalled") || time.Since(start) > 3*time.Second {
		t.Fatalf("stall not detected in time (%v):\n%s", time.Since(start), got)
	}
	time.Sleep(100 * time.Millisecond)
	if !cancelled.Load() {
		t.Fatal("stalled upstream not cancelled")
	}
}

func TestStreamClientDisconnectCancelsUpstream(t *testing.T) {
	var cancelled atomic.Bool
	pieces := make([]string, 200)
	for i := range pieces {
		pieces[i] = "data: " + chunkJSON(i, "x") + "\n\n"
	}
	r, _ := startAPI(t, sseUpstream(pieces, 20*time.Millisecond, &cancelled), nil)
	resp := streamPost(t, r, streamReq)
	br := bufio.NewReader(resp.Body)
	for i := 0; i < 3; i++ {
		_, _ = br.ReadString('\n')
	}
	resp.Body.Close() // client walks away
	deadline := time.Now().Add(2 * time.Second)
	for !cancelled.Load() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !cancelled.Load() {
		t.Fatal("upstream kept generating after the client disconnected (tokens would be paid for nobody)")
	}
}

func TestStreamSlowClientIsCutOff(t *testing.T) {
	var cancelled atomic.Bool
	big := "data: " + chunkJSON(0, strings.Repeat("A", 256<<10)) + "\n\n"
	pieces := make([]string, 400)
	for i := range pieces {
		pieces[i] = big
	}
	r, _ := startAPI(t, sseUpstream(pieces, 0, &cancelled), func(c *config.Config) {
		c.Limits.WriteDeadline = 300 * time.Millisecond
		c.Limits.EventBytes = 1 << 20
	})
	// A client that sends the request and never reads.
	c, err := net.Dial("tcp", strings.TrimPrefix(r.dataURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4096)
	}
	fmt.Fprintf(c, "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", r.key, len(streamReq), streamReq)
	deadline := time.Now().Add(5 * time.Second)
	for !cancelled.Load() && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !cancelled.Load() {
		t.Fatal("a client that never reads kept the upstream stream alive past the write deadline")
	}
}

func TestStreamLimits(t *testing.T) {
	long := []string{"data: " + chunkJSON(0, strings.Repeat("x", 4000)) + "\n\n", "data: [DONE]\n\n"}
	r, _ := startAPI(t, sseUpstream(long, 0, nil), func(c *config.Config) { c.Limits.EventBytes = 1000 })
	if got := readAll(streamPost(t, r, streamReq)); !strings.Contains(got, "event_too_large") {
		t.Errorf("event cap:\n%.200s", got)
	}
	many := make([]string, 50)
	for i := range many {
		many[i] = "data: " + chunkJSON(i, strings.Repeat("y", 500)) + "\n\n"
	}
	r, _ = startAPI(t, sseUpstream(many, 0, nil), func(c *config.Config) { c.Limits.StreamBytes = 5000 })
	if got := readAll(streamPost(t, r, streamReq)); !strings.Contains(got, "stream_too_large") {
		t.Errorf("byte cap:\n%.200s", got)
	}
	slow := make([]string, 100)
	for i := range slow {
		slow[i] = "data: " + chunkJSON(i, "z") + "\n\n"
	}
	r, _ = startAPI(t, sseUpstream(slow, 50*time.Millisecond, nil), func(c *config.Config) { c.Limits.StreamDuration = 300 * time.Millisecond })
	if got := readAll(streamPost(t, r, streamReq)); !strings.Contains(got, "stream_timeout") {
		t.Errorf("duration cap:\n%.300s", got)
	}
}

func TestStreamPerAgentCap(t *testing.T) {
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: "+chunkJSON(0, "a")+"\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-rq.Context().Done():
		}
		io.WriteString(w, "data: [DONE]\n\n")
	})
	r, _ := startAPI(t, h, func(c *config.Config) { c.Agents[0].Limits.ConcurrentStreams = 1 })
	first := streamPost(t, r, streamReq)
	br := bufio.NewReader(first.Body)
	_, _ = br.ReadString('\n') // first event arrived: the slot is held
	second := streamPost(t, r, streamReq)
	body := readAll(second)
	if second.StatusCode != 429 || !strings.Contains(body, "too_many_streams") || second.Header.Get("Retry-After") == "" {
		t.Fatalf("%d %s", second.StatusCode, body)
	}
	close(release)
	first.Body.Close()
	time.Sleep(100 * time.Millisecond)
	third := streamPost(t, r, streamReq)
	if third.StatusCode != 200 {
		t.Fatalf("slot not released: %d", third.StatusCode)
	}
	third.Body.Close()
}

func TestStreamUpstreamErrorStatusIsRelayedAsJSON(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(429)
		io.WriteString(w, `{"error":{"message":"rate limited"}}`)
	})
	r, _ := startAPI(t, h, nil)
	resp := streamPost(t, r, streamReq)
	body := readAll(resp)
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") != "3" || !strings.Contains(body, "rate limited") {
		t.Fatalf("%d %v %s", resp.StatusCode, resp.Header, body)
	}
}

func countFDs(t *testing.T) int {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc")
	}
	return len(ents)
}

// Churn: many streams, half aborted by the client mid-flight. Afterwards the
// goroutine and descriptor counts must return to (about) where they started.
func TestNoGoroutineOrFDLeakAfterChurn(t *testing.T) {
	pieces := make([]string, 30)
	for i := range pieces {
		pieces[i] = "data: " + chunkJSON(i, "x") + "\n\n"
	}
	pieces = append(pieces, "data: [DONE]\n\n")
	r, _ := startAPI(t, sseUpstream(pieces, 2*time.Millisecond, nil), nil)
	tr := &http.Transport{DisableKeepAlives: true}
	client := &http.Client{Transport: tr}
	one := func(abort bool) {
		req, _ := http.NewRequest("POST", r.dataURL+"/v1/chat/completions", strings.NewReader(streamReq))
		req.Header.Set("Authorization", "Bearer "+r.key)
		req.Header.Set("Content-Type", "application/json")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		resp, err := client.Do(req.WithContext(ctx))
		if err != nil {
			return
		}
		if abort {
			br := bufio.NewReader(resp.Body)
			_, _ = br.ReadString('\n')
			cancel()
			resp.Body.Close()
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	for i := 0; i < 5; i++ { // warm pools
		one(false)
	}
	time.Sleep(300 * time.Millisecond)
	g0, f0 := runtime.NumGoroutine(), countFDs(t)
	var wg sync.WaitGroup
	for batch := 0; batch < 20; batch++ {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(abort bool) { defer wg.Done(); one(abort) }(i%2 == 0)
		}
		wg.Wait()
	}
	tr.CloseIdleConnections()
	var g1, f1 int
	for i := 0; i < 40; i++ { // allow lingering goroutines/conns to wind down
		time.Sleep(100 * time.Millisecond)
		g1, f1 = runtime.NumGoroutine(), countFDs(t)
		if g1 <= g0+6 && f1 <= f0+6 {
			break
		}
	}
	if g1 > g0+6 || f1 > f0+6 {
		t.Fatalf("leak after 200 streams (half aborted): goroutines %d -> %d, fds %d -> %d", g0, g1, f0, f1)
	}
	if n := bytes.Count([]byte(fmt.Sprint(r.s.m.inflight)), []byte("x")); n < 0 {
		t.Fatal("unreachable")
	}
}

// HTTP/2 stress (IMPLEMENTATION_PLAN Phase 1 risk table): many concurrent
// streams multiplexed over a few h2c connections must all complete, in order,
// with no stream starved.
func TestH2ManyConcurrentStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("stress")
	}
	const streams, conns, events = 400, 4, 40
	pieces := make([]string, 0, events+1)
	for i := 0; i < events; i++ {
		pieces = append(pieces, "data: "+chunkJSON(i, fmt.Sprintf("t%02d ", i))+"\n\n")
	}
	pieces = append(pieces, "data: [DONE]\n\n")
	r, _ := startAPI(t, sseUpstream(pieces, 3*time.Millisecond, nil), func(c *config.Config) {
		c.Listen.H2C = true
		c.Limits.GlobalInflight = 100000
	})
	var clients []*http.Client
	for i := 0; i < conns; i++ {
		p := new(http.Protocols)
		p.SetUnencryptedHTTP2(true)
		clients = append(clients, &http.Client{Transport: &http.Transport{Protocols: p, MaxConnsPerHost: 1, HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 1000}}})
	}
	var wg sync.WaitGroup
	var bad, worstGapMS atomic.Int64
	start := time.Now()
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, _ := http.NewRequest("POST", r.dataURL+"/v1/chat/completions", strings.NewReader(streamReq))
			req.Header.Set("Authorization", "Bearer "+r.key)
			req.Header.Set("Content-Type", "application/json")
			resp, err := clients[i%conns].Do(req)
			if err != nil || resp.StatusCode != 200 || resp.ProtoMajor != 2 {
				bad.Add(1)
				return
			}
			defer resp.Body.Close()
			br := bufio.NewReader(resp.Body)
			last, next := time.Now(), 0
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					bad.Add(1)
					return
				}
				if strings.HasPrefix(line, "data: [DONE]") {
					break
				}
				if strings.HasPrefix(line, "data: {") {
					if !strings.Contains(line, fmt.Sprintf("t%02d ", next)) { // order preserved
						bad.Add(1)
						return
					}
					next++
					if g := time.Since(last).Milliseconds(); g > worstGapMS.Load() {
						worstGapMS.Store(g)
					}
					last = time.Now()
				}
			}
			if next != events {
				bad.Add(1)
			}
		}(i)
	}
	wg.Wait()
	t.Logf("%d streams over %d h2c connections in %v; worst inter-event gap seen by a client: %dms (upstream gap 3ms)", streams, conns, time.Since(start).Round(time.Millisecond), worstGapMS.Load())
	if bad.Load() != 0 {
		t.Fatalf("%d of %d streams failed, were reordered or lost events", bad.Load(), streams)
	}
	if worstGapMS.Load() > 1500 {
		t.Fatalf("a stream was starved for %dms under h2 multiplexing", worstGapMS.Load())
	}
}
