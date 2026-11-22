package mock

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/vivekjami/tripwire/internal/clock"
)

// Responses API subset (ARCHITECTURE §4.3): typed semantic events, each with
// sequence_number, delta events carrying an `obfuscation` padding field, and
// no [DONE] sentinel. Events: response.created, response.output_text.delta,
// response.output_text.done, response.completed.

type respReq struct {
	Stream   bool              `json:"stream"`
	Model    string            `json:"model"`
	Metadata map[string]string `json:"metadata"`
}

func (s *Server) handleResponses(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req respReq
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	spec, err := s.specFrom(req.Metadata["tw_mock"], "responses")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pl, err := s.makePlan(spec, "responses")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.waitStall()
	s.recordGT(pl)
	s.started.Add(1)
	defer s.done.Add(1)

	rid := "resp_" + spec.StreamID
	if !req.Stream {
		var total time.Duration
		for _, g := range pl.gaps {
			total += g
		}
		time.Sleep(total)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": rid, "object": "response", "status": "completed", "model": "mock-1",
			"output": []any{map[string]any{"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
				"content": []any{map[string]any{"type": "output_text", "text": pl.text}}}},
		})
		return
	}

	sseHeaders(w)
	w.WriteHeader(http.StatusOK)
	em := s.newEmitter(w, spec.StreamID)
	defer em.close()
	if em.rc.Flush() != nil {
		return
	}

	seq := 0
	frame := func(typ string, fields func(b []byte) []byte) []byte {
		b := append([]byte(nil), "event: "+typ+"\ndata: {\"type\":\""+typ+"\",\"sequence_number\":"...)
		b = strconv.AppendInt(b, int64(seq), 10)
		seq++
		b = fields(b)
		return append(b, "}\n\n"...)
	}
	t := clock.Now()
	if em.send(t, frame("response.created", func(b []byte) []byte {
		return append(b, `,"response":{"id":"`+rid+`","status":"in_progress","model":"mock-1"}`...)
	})) != nil {
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
				if em.send(t, []byte("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"\n\n")) != nil {
					return
				}
			}
		}
		fr := frame("response.output_text.delta", func(b []byte) []byte {
			b = append(b, `,"item_id":"msg_1","output_index":0,"content_index":0,"delta":`...)
			b = p.appendJSON(b, pl.ascii[i])
			return append(b, `,"obfuscation":"`+obfuscation(i)+`"`...)
		})
		if em.send(t, fr) != nil {
			return
		}
	}
	if em.send(t, frame("response.output_text.done", func(b []byte) []byte {
		b = append(b, `,"item_id":"msg_1","output_index":0,"content_index":0,"text":`...)
		return append(b, mustJSON(pl.text)...)
	})) != nil {
		return
	}
	_ = em.send(t, frame("response.completed", func(b []byte) []byte {
		b = append(b, `,"response":{"id":"`+rid+`","status":"completed","model":"mock-1","output":[{"type":"message","id":"msg_1","role":"assistant","content":[{"type":"output_text","text":`...)
		b = append(b, mustJSON(pl.text)...)
		return append(b, `}]}]}`...)
	}))
}

func obfuscation(i int) string {
	const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	n := 5 + i%7
	b := make([]byte, n)
	for j := range b {
		b[j] = a[(i*31+j*17)%len(a)]
	}
	return string(b)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
