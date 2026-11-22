package load

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/vivekjami/tripwire/internal/clock"
	"github.com/vivekjami/tripwire/internal/groundtruth"
)

const (
	mcpStateless = "2026-07-28"
	mcpLegacy    = "2025-11-25"
)

// session lazily performs the legacy `initialize` handshake once per run.
func (r *Runner) session() (string, error) {
	r.mcpSessOnce.Do(func() {
		body := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"` + mcpLegacy + `","capabilities":{},"clientInfo":{"name":"twload","version":"0"}}}`
		req, err := http.NewRequestWithContext(r.ctx, http.MethodPost, r.cfg.Target+"/mcp", bytes.NewReader([]byte(body)))
		if err != nil {
			r.mcpSessErr = err
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("MCP-Protocol-Version", mcpLegacy)
		resp, err := r.client.Do(req)
		if err != nil {
			r.mcpSessErr = err
			return
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		r.mcpSessID = resp.Header.Get("Mcp-Session-Id")
	})
	return r.mcpSessID, r.mcpSessErr
}

// doMCP issues one tools/call. When MCPMismatchFrac > 0 and the revision is the
// stateless one, a fraction of requests carry an Mcp-Name header that
// contradicts the body; a correct server or gateway MUST reject these, and the
// counters mcp_mismatch_rejected / mcp_mismatch_accepted record whether it did.
func (r *Runner) doMCP(id string, seq int64, events int) outcome {
	c := r.cfg
	sp := r.specFor(id, seq, events)
	sj, _ := json.Marshal(sp)
	type params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": seq + 1, "method": "tools/call",
		"params": params{Name: c.MCPTool, Arguments: map[string]any{"tw_mock": string(sj)}},
	})

	ctx, cancel := context.WithTimeout(r.ctx, c.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Target+"/mcp", bytes.NewReader(body))
	if err != nil {
		return outcome{err: "build_request"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", c.MCPVersion)
	mismatch := false
	switch c.MCPVersion {
	case mcpStateless:
		req.Header.Set("Mcp-Method", "tools/call")
		name := c.MCPTool
		if unit(c.Seed, seq, 17) < c.MCPMismatchFrac {
			mismatch, name = true, "send_email"
			if name == c.MCPTool {
				name = "echo"
			}
		}
		req.Header.Set("Mcp-Name", name)
	case mcpLegacy:
		sid, err := r.session()
		if err != nil {
			return outcome{err: "mcp_session"}
		}
		req.Header.Set("Mcp-Session-Id", sid)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return outcome{err: classifyErr(err)}
	}
	defer resp.Body.Close()
	o := outcome{hdrAt: clock.Now()}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return outcome{err: classifyErr(err)}
	}
	o.firstEvent, o.events = clock.Now(), 1

	if mismatch {
		if resp.StatusCode == http.StatusOK && bytes.Contains(raw, []byte(`"result"`)) {
			r.mcpAcc.Add(1)
		} else {
			r.mcpRej.Add(1)
		}
		return o // expected-rejection requests are not latency samples of normal calls
	}
	if resp.StatusCode != http.StatusOK {
		return outcome{err: "status_" + strconv.Itoa(resp.StatusCode)}
	}
	rpc := raw
	if ct := resp.Header.Get("Content-Type"); len(ct) >= 17 && ct[:17] == "text/event-stream" {
		rpc = lastSSEData(raw)
	}
	var out struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(rpc, &out); err != nil || len(out.Error) > 0 {
		return outcome{err: "mcp_error"}
	}
	r.mcpOK.Add(1)
	if c.GTLog != "" && groundtruth.Sampled(id+"#check", c.CheckSample) && len(out.Result.Content) > 0 {
		o.check = &checkItem{id: id, text: out.Result.Content[0].Text, complete: true}
	}
	return o
}

// lastSSEData returns the data payload of the final event in an SSE body.
func lastSSEData(raw []byte) []byte {
	var last []byte
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		if b, ok := bytes.CutPrefix(sc.Bytes(), []byte("data:")); ok {
			last = bytes.TrimLeft(append([]byte(nil), b...), " ")
		}
	}
	return last
}
