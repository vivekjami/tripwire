package mock

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/vivekjami/tripwire/internal/clock"
)

var bufPool = sync.Pool{New: func() any { b := make([]byte, 0, 1024); return &b }}

type chatReq struct {
	Stream   bool              `json:"stream"`
	Model    string            `json:"model"`
	Metadata map[string]string `json:"metadata"`
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req chatReq
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	spec, err := s.specFrom(req.Metadata["tw_mock"], "chat")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pl, err := s.makePlan(spec, "chat")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.waitStall()
	s.recordGT(pl)
	model := req.Model
	if model == "" {
		model = "mock-1"
	}
	if !req.Stream {
		s.chatJSON(w, pl, model)
		return
	}
	s.chatStream(w, pl, model)
}

func (s *Server) chatJSON(w http.ResponseWriter, pl *plan, model string) {
	var total time.Duration
	for _, g := range pl.gaps {
		total += g
	}
	s.started.Add(1)
	defer s.done.Add(1)
	time.Sleep(total)
	out := map[string]any{
		"id": "chatcmpl-" + pl.spec.StreamID, "object": "chat.completion", "created": time.Now().Unix(), "model": model,
		"choices": []any{map[string]any{"index": 0, "finish_reason": "stop",
			"message": map[string]any{"role": "assistant", "content": pl.text}}},
		"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": len(pl.pieces), "total_tokens": 10 + len(pl.pieces)},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func chatChunkPrefix(dst []byte, id, model string, created int64) []byte {
	dst = append(dst, `data: {"id":"chatcmpl-`...)
	dst = append(dst, id...)
	dst = append(dst, `","object":"chat.completion.chunk","created":`...)
	dst = strconv.AppendInt(dst, created, 10)
	dst = append(dst, `,"model":"`...)
	dst = append(dst, model...)
	return append(dst, `","choices":[{"index":0,`...)
}

func (s *Server) chatStream(w http.ResponseWriter, pl *plan, model string) {
	s.started.Add(1)
	defer s.done.Add(1)
	sseHeaders(w)
	w.WriteHeader(http.StatusOK)
	em := s.newEmitter(w, pl.spec.StreamID)
	defer em.close()
	if err := em.rc.Flush(); err != nil {
		return
	}

	id, created := pl.spec.StreamID, time.Now().Unix()
	bp := bufPool.Get().(*[]byte)
	defer func() { bufPool.Put(bp) }()
	buf := (*bp)[:0]

	buf = chatChunkPrefix(buf, id, model, created)
	buf = append(buf, `"delta":{"role":"assistant","content":""},"finish_reason":null}]}`+"\n\n"...)
	t := clock.Now()
	if em.send(t, buf) != nil {
		return
	}

	for i, p := range pl.pieces {
		t += int64(pl.gaps[i])
		if f := pl.faultAt(i); f != nil {
			switch f.Kind {
			case "reset":
				abortConn(w)
				return
			case "stall":
				time.Sleep(f.stallDur())
				if now := clock.Now(); now > t {
					t = now
				}
			case "malformed":
				if em.send(t, []byte(`data: {"id":"x","choices":[{"index":0,"delta":{"content":"`+"\n\n")) != nil {
					return
				}
			case "oversize":
				big := append([]byte(`data: {"choices":[{"index":0,"delta":{"content":"`), bytes.Repeat([]byte{'a'}, 2<<20)...)
				big = append(big, `"}}]}`+"\n\n"...)
				if em.send(t, big) != nil {
					return
				}
			}
		}
		buf = chatChunkPrefix(buf[:0], id, model, created)
		buf = append(buf, `"delta":{"content":`...)
		f := pl.faultAt(i)
		switch {
		case f != nil && f.Kind == "badutf8":
			buf = append(buf, '"', 0xFF)
			buf = append(buf, p.appendJSON(nil, pl.ascii[i])[1:]...)
		default:
			buf = p.appendJSON(buf, pl.ascii[i])
		}
		if f != nil && f.Kind == "dupkey" {
			buf = append(buf, `,"content":"DUP"`...)
		}
		buf = append(buf, `},"finish_reason":null}]}`+"\n\n"...)
		if em.send(t, buf) != nil {
			return
		}
	}

	buf = chatChunkPrefix(buf[:0], id, model, created)
	buf = append(buf, `"delta":{},"finish_reason":"stop"}]}`+"\n\n"...)
	if em.send(t, buf) != nil {
		return
	}
	_ = em.send(t, []byte("data: [DONE]\n\n"))
}
