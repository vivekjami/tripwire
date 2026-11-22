// Package mock implements twmock: an OpenAI-compatible LLM mock and an MCP mock
// whose behaviour (stream shape, chunking, injected sensitive values, faults)
// is controlled per request, deterministically by seed, and whose every
// injection is written to a ground-truth log.
//
// Control channel. The mock is steered by a JSON document carried in the
// standard `metadata.tw_mock` request field (a string, as OpenAI metadata
// values must be). It travels in the body rather than in headers so that a
// gateway's outbound-header allow-list (ARCHITECTURE T18) cannot silently strip
// it, and it is a legal OpenAI field so the request stays schema-valid.
package mock

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strings"
	"time"
)

// Inject asks for Count fake values of Class to be embedded in the response.
type Inject struct {
	Class string `json:"class"`
	Count int    `json:"count"`
}

// Fault selects a deterministic upstream misbehaviour.
//
// Kinds: reset (TCP RST / abort mid-stream), stall (pause Stall at AtEvent),
// malformed (truncated JSON event), oversize (≈2 MiB event), dupkey (duplicate
// "content" key in one event), badutf8 (raw 0xFF byte inside a string).
type Fault struct {
	Kind    string `json:"kind"`
	AtEvent int    `json:"at_event"`
	Stall   string `json:"stall,omitempty"` // duration, for kind=stall
}

// Spec is the per-request mock control document.
type Spec struct {
	StreamID string   `json:"stream_id"`
	Events   int      `json:"events,omitempty"` // approximate number of content events
	Gap      string   `json:"gap,omitempty"`    // none | const:20ms | lognormal:20ms,0.4 | file:path
	Chunk    string   `json:"chunk,omitempty"`  // token | per-char | random:0.3 | boundary | adversarial
	Escape   string   `json:"escape,omitempty"` // raw | ascii | mixed (default mixed)
	Inject   []Inject `json:"inject,omitempty"`
	Fault    *Fault   `json:"fault,omitempty"`
	Seed     int64    `json:"seed,omitempty"`
	SSE      bool     `json:"sse,omitempty"` // MCP: answer tools/call over text/event-stream
}

// ParseSpec parses a tw_mock string. An empty string yields a zero Spec.
func ParseSpec(s string) (Spec, error) {
	var sp Spec
	if strings.TrimSpace(s) == "" {
		return sp, nil
	}
	if err := json.Unmarshal([]byte(s), &sp); err != nil {
		return sp, fmt.Errorf("tw_mock: %w", err)
	}
	for _, in := range sp.Inject {
		if in.Count < 0 || in.Count > 64 {
			return sp, fmt.Errorf("tw_mock: inject count %d out of range", in.Count)
		}
	}
	if sp.Events < 0 {
		return sp, fmt.Errorf("tw_mock: negative events")
	}
	return sp, nil
}

// seedFor derives the effective PRNG seed.
func (sp Spec) seedFor() int64 {
	if sp.Seed != 0 {
		return sp.Seed
	}
	h := fnv.New64a()
	h.Write([]byte(sp.StreamID))
	return int64(h.Sum64() >> 1)
}

// FaultStall parses Fault.Stall.
func (f *Fault) stallDur() time.Duration {
	if f == nil || f.Stall == "" {
		return 0
	}
	d, err := time.ParseDuration(f.Stall)
	if err != nil {
		return 0
	}
	return d
}
