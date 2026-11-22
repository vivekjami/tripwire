package mock

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vivekjami/tripwire/internal/groundtruth"
)

func chatBody(t *testing.T, stream bool, spec Spec) string {
	t.Helper()
	sb, _ := json.Marshal(spec)
	body, _ := json.Marshal(map[string]any{
		"model": "mock-1", "stream": stream,
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
		"metadata": map[string]string{"tw_mock": string(sb)},
	})
	return string(body)
}

type sseEvent struct{ event, data string }

func readSSE(t *testing.T, body io.Reader) []sseEvent {
	t.Helper()
	var out []sseEvent
	var cur sseEvent
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if cur.data != "" {
				out = append(out, cur)
			}
			cur = sseEvent{}
		case strings.HasPrefix(line, "event: "):
			cur.event = line[7:]
		case strings.HasPrefix(line, "data: "):
			cur.data += line[6:]
		}
	}
	return out
}

// clientText reassembles content the way a careful client must: JSON string
// literals are decoded to UTF-16 units so split surrogates rejoin.
func clientText(t *testing.T, evs []sseEvent, surface string) string {
	t.Helper()
	var units []uint16
	for _, e := range evs {
		if e.data == "[DONE]" {
			continue
		}
		var raw json.RawMessage
		switch surface {
		case "chat":
			var c struct {
				Choices []struct {
					Delta struct {
						Content json.RawMessage `json:"content"`
					} `json:"delta"`
				} `json:"choices"`
			}
			if err := json.Unmarshal([]byte(e.data), &c); err != nil {
				t.Fatalf("event %q: %v", e.data, err)
			}
			if len(c.Choices) == 0 || len(c.Choices[0].Delta.Content) == 0 {
				continue
			}
			raw = c.Choices[0].Delta.Content
		case "responses":
			var c struct {
				Type  string          `json:"type"`
				Delta json.RawMessage `json:"delta"`
			}
			if err := json.Unmarshal([]byte(e.data), &c); err != nil {
				t.Fatalf("event %q: %v", e.data, err)
			}
			if c.Type != "response.output_text.delta" {
				continue
			}
			raw = c.Delta
		}
		u, err := groundtruth.DecodeJSONString(raw)
		if err != nil {
			t.Fatalf("decode %s: %v", raw, err)
		}
		units = append(units, u...)
	}
	return groundtruth.UnitsToString(units)
}

func newTestServer(t *testing.T, mutate func(*Config)) (*Server, *httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	gtw, err := groundtruth.NewWriter(filepath.Join(dir, "gt.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ew, err := groundtruth.NewEmitWriter(filepath.Join(dir, "emit.csv"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{GroundTruth: gtw, Emit: ew, EmitSample: 1}
	if mutate != nil {
		mutate(&cfg)
	}
	s := New(cfg)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { ts.Close(); gtw.Close(); ew.Close() })
	return s, ts, dir
}

func TestChatStreamGroundTruthEveryChunking(t *testing.T) {
	srv, ts, dir := newTestServer(t, nil)
	for _, chunk := range []string{"token", "per-char", "random:0.4", "boundary", "adversarial"} {
		spec := Spec{StreamID: "s-" + chunk, Events: 80, Gap: "none", Chunk: chunk, Seed: 11,
			Inject: []Inject{{"PCI.PAN", 2}, {"SECRET.AWS_ACCESS_KEY", 1}, {"PII.CONTACT.EMAIL", 1}}}
		resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", strings.NewReader(chatBody(t, true, spec)))
		if err != nil {
			t.Fatal(err)
		}
		evs := readSSE(t, resp.Body)
		resp.Body.Close()
		if evs[len(evs)-1].data != "[DONE]" {
			t.Fatalf("%s: stream did not end with [DONE]", chunk)
		}
		text := clientText(t, evs, "chat")

		// pass-through == nothing redacted: every span MUST be present verbatim
		gtMap := loadGT(t, srv, dir)
		gt := gtMap[spec.StreamID]
		if gt == nil {
			t.Fatalf("%s: no ground truth", chunk)
		}
		if len(gt.Spans) != 4 {
			t.Fatalf("%s: spans=%d", chunk, len(gt.Spans))
		}
		if groundtruth.HashText(text) != gt.TextHash {
			t.Fatalf("%s: client text hash differs from ground truth\n got %q", chunk, text)
		}
		res := groundtruth.Check(gt, text)
		if len(res.Leaks) != 4 {
			t.Fatalf("%s: unmodified pass-through must 'leak' all 4 spans (harness sanity), got %d", chunk, len(res.Leaks))
		}
		for _, sp := range gt.Spans {
			if text[sp.Offset:sp.Offset+sp.Len] != sp.Value {
				t.Fatalf("%s: span offset does not index into client text", chunk)
			}
		}
		if got := gt.EventEnds[len(gt.EventEnds)-1]; got != gt.TextLen {
			t.Fatalf("%s: last event end %d != text len %d", chunk, got, gt.TextLen)
		}
	}
}

// loadGT flushes the server's buffered ground-truth writer and re-reads the file.
func loadGT(t *testing.T, s *Server, dir string) map[string]*groundtruth.Stream {
	t.Helper()
	if err := s.cfg.GroundTruth.Flush(); err != nil {
		t.Fatal(err)
	}
	m, err := groundtruth.Load(filepath.Join(dir, "gt.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func nowMS() int64 { return time.Now().UnixMilli() }

func TestResponsesStream(t *testing.T) {
	_, ts, _ := newTestServer(t, nil)
	spec := Spec{StreamID: "r1", Events: 40, Gap: "none", Chunk: "token", Seed: 3, Inject: []Inject{{"PCI.PAN", 1}}}
	resp, err := http.Post(ts.URL+"/v1/responses", "application/json", strings.NewReader(chatBody(t, true, spec)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	evs := readSSE(t, resp.Body)
	if evs[0].event != "response.created" || evs[len(evs)-1].event != "response.completed" {
		t.Fatalf("event order wrong: first=%s last=%s", evs[0].event, evs[len(evs)-1].event)
	}
	// sequence_number monotone from 0, obfuscation present on deltas
	for i, e := range evs {
		var m struct {
			Seq  int    `json:"sequence_number"`
			Obf  string `json:"obfuscation"`
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(e.data), &m); err != nil {
			t.Fatal(err)
		}
		if m.Seq != i {
			t.Fatalf("sequence_number %d at index %d", m.Seq, i)
		}
		if m.Type == "response.output_text.delta" && m.Obf == "" {
			t.Fatal("delta missing obfuscation field")
		}
	}
	if text := clientText(t, evs, "responses"); !strings.Contains(text, " ") {
		t.Fatal("empty reassembled text")
	}
}

func TestNonStream(t *testing.T) {
	_, ts, _ := newTestServer(t, nil)
	spec := Spec{StreamID: "n1", Events: 30, Gap: "none", Seed: 9, Inject: []Inject{{"PCI.PAN", 1}}}
	resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", strings.NewReader(chatBody(t, false, spec)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Choices []struct {
			Message struct{ Content string } `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || len(out.Choices) != 1 {
		t.Fatalf("bad body: %v", err)
	}
	if out.Choices[0].Message.Content == "" {
		t.Fatal("empty content")
	}
}

func TestFaultKinds(t *testing.T) {
	_, ts, _ := newTestServer(t, nil)
	run := func(kind string) (string, error) {
		spec := Spec{StreamID: "f-" + kind, Events: 20, Gap: "none", Seed: 5, Fault: &Fault{Kind: kind, AtEvent: 3, Stall: "5ms"}}
		resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", strings.NewReader(chatBody(t, true, spec)))
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return string(b), err
	}
	if _, err := run("reset"); err == nil {
		t.Error("reset: expected a read error from an aborted connection")
	}
	if b, err := run("stall"); err != nil || !strings.HasSuffix(b, "data: [DONE]\n\n") {
		t.Errorf("stall: should still complete: err=%v", err)
	}
	if b, _ := run("malformed"); !strings.Contains(b, `"content":"`+"\n\n") {
		t.Error("malformed: truncated event not found")
	}
	if b, _ := run("oversize"); len(b) < 2<<20 {
		t.Errorf("oversize: only %d bytes", len(b))
	}
	if b, _ := run("dupkey"); !strings.Contains(b, `"content":"DUP"`) {
		t.Error("dupkey: duplicate key not emitted")
	}
	if b, _ := run("badutf8"); !strings.Contains(b, "\"\xff") {
		t.Error("badutf8: invalid byte not emitted")
	}
}

func TestMCPStatelessHeaderEnforcement(t *testing.T) {
	_, ts, _ := newTestServer(t, nil)
	post := func(body string, hdr map[string]string) (int, string) {
		req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("MCP-Protocol-Version", "2026-07-28")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_customer","arguments":{"tw_mock":"{\"stream_id\":\"m1\",\"inject\":[{\"class\":\"PCI.PAN\",\"count\":1}]}"}}}`
	if c, b := post(call, map[string]string{"Mcp-Method": "tools/call", "Mcp-Name": "get_customer"}); c != 200 || !strings.Contains(b, `"result"`) {
		t.Fatalf("good request rejected: %d %s", c, b)
	}
	if c, _ := post(call, map[string]string{"Mcp-Method": "tools/list", "Mcp-Name": "get_customer"}); c != 400 {
		t.Fatalf("Mcp-Method mismatch accepted: %d", c)
	}
	if c, _ := post(call, map[string]string{"Mcp-Method": "tools/call", "Mcp-Name": "send_email"}); c != 400 {
		t.Fatalf("Mcp-Name mismatch accepted: %d", c)
	}
	if c, _ := post(call, nil); c != 400 {
		t.Fatalf("missing headers accepted: %d", c)
	}
}

func TestMCPLegacySessions(t *testing.T) {
	_, ts, _ := newTestServer(t, nil)
	do := func(body, sid string) (*http.Response, string) {
		req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("MCP-Protocol-Version", "2025-11-25")
		if sid != "" {
			req.Header.Set("Mcp-Session-Id", sid)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	if resp, _ := do(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, ""); resp.StatusCode != 404 {
		t.Fatalf("sessionless call accepted: %d", resp.StatusCode)
	}
	resp, _ := do(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "")
	sid := resp.Header.Get("Mcp-Session-Id")
	if resp.StatusCode != 200 || sid == "" {
		t.Fatalf("initialize failed: %d sid=%q", resp.StatusCode, sid)
	}
	if resp, b := do(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, sid); resp.StatusCode != 200 || !strings.Contains(b, "get_customer") {
		t.Fatalf("tools/list with session failed: %d %s", resp.StatusCode, b)
	}
}

func TestMCPHostileRugPull(t *testing.T) {
	_, ts, _ := newTestServer(t, func(c *Config) { c.Hostile = true; c.HostileAfter = 1; c.MCPDefaultVersion = "2026-07-28" })
	list := func() string {
		req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Mcp-Method", "tools/list")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if strings.Contains(list(), "IMPORTANT") {
		t.Fatal("description mutated too early")
	}
	if !strings.Contains(list(), "IMPORTANT") {
		t.Fatal("description did not mutate after threshold (rug pull)")
	}
}

func TestStallAndStats(t *testing.T) {
	s, ts, _ := newTestServer(t, nil)
	resp, err := http.Post(ts.URL+"/_tw/stall?ms=50", "", nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("stall endpoint: %v", err)
	}
	resp.Body.Close()
	spec := Spec{StreamID: "st", Events: 5, Gap: "none"}
	t0 := nowMS()
	r2, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", strings.NewReader(chatBody(t, true, spec)))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, r2.Body)
	r2.Body.Close()
	if d := nowMS() - t0; d < 40 {
		t.Fatalf("request returned after %dms during a 50ms stall", d)
	}
	if st := s.Stats(); st.StreamsDone != 1 || st.EventsEmitted == 0 {
		t.Fatalf("stats wrong: %+v", st)
	}
}
