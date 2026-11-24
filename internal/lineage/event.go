// Package lineage is the event pipeline between the data path and storage
// (ARCHITECTURE §10.7): pooled event structs, a lock-free MPSC ring that never
// blocks the hot path, batching writers, and sinks (null, memory, ClickHouse).
// The structs mirror deploy/ch/migrations column for column (provisional
// freeze, WP1.6).
package lineage

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/vivekjami/tripwire/internal/obs"
)

// Kind selects which table an Event belongs to.
type Kind uint8

// Event kinds.
const (
	KindRequest Kind = iota + 1
	KindTag
	KindFlow
	KindFinding
)

// Event is the unit that crosses the ring. Only the member matching Kind is
// meaningful. It is pooled: producers obtain one with NewEvent and hand it to
// Emit, which transfers ownership.
type Event struct {
	Kind    Kind
	Request obs.RequestEvent
	Tag     TagEvent
	Flow    FlowEvent
	Finding FindingEvent
}

var pool = sync.Pool{New: func() any { return new(Event) }}

// NewEvent returns a zeroed event of the given kind.
func NewEvent(k Kind) *Event {
	e := pool.Get().(*Event)
	*e = Event{Kind: k}
	return e
}

func release(e *Event) { pool.Put(e) }

// The structs below mirror the DDL; field order == column order. The `ch` tag is
// the column name. They contain no raw values (ARCHITECTURE §10.6, T12/T14).

// TagEvent: a sensitive value observed at a source.
type TagEvent struct {
	TenantID       string    `ch:"tenant_id"`
	SessionID      [16]byte  `ch:"session_id"`
	TS             time.Time `ch:"ts"`
	EventID        uint64    `ch:"event_id"`
	TagID          [16]byte  `ch:"tag_id"`
	KeyEpoch       uint16    `ch:"key_epoch"`
	DataClass      string    `ch:"data_class"`
	SourceKind     uint8     `ch:"source_kind"`
	SourceServer   string    `ch:"source_server"`
	SourceTool     string    `ch:"source_tool"`
	SourceCallHash uint64    `ch:"source_call_hash"`
	SourceRefHash  uint64    `ch:"source_ref_hash"`
	AgentID        string    `ch:"agent_id"`
	Confidence     uint8     `ch:"confidence"`
	Preview        [4]byte   `ch:"preview"`
	TraceID        [16]byte  `ch:"trace_id"`
}

// FlowEvent: a tagged value observed at a sink, with the policy outcome.
type FlowEvent struct {
	TenantID  string    `ch:"tenant_id"`
	SessionID [16]byte  `ch:"session_id"`
	TS        time.Time `ch:"ts"`
	EventID   uint64    `ch:"event_id"`
	TagID     [16]byte  `ch:"tag_id"`
	EdgeKind  uint8     `ch:"edge_kind"`
	SinkKind  uint8     `ch:"sink_kind"`
	SinkName  string    `ch:"sink_name"`
	SinkTier  string    `ch:"sink_tier"`
	Direction uint8     `ch:"direction"`
	AgentID   string    `ch:"agent_id"`
	DataClass string    `ch:"data_class"`
	Action    uint8     `ch:"action"`
	Mode      uint8     `ch:"mode"`
	RuleID    string    `ch:"rule_id"`
	PolicyVer uint32    `ch:"policy_ver"`
	MsgIndex  uint16    `ch:"msg_index"`
	SpanStart uint32    `ch:"span_start"`
	SpanLen   uint16    `ch:"span_len"`
	WouldHave uint8     `ch:"would_have"`
	TraceID   [16]byte  `ch:"trace_id"`
}

// FindingEvent: an injection or anomaly finding with provenance.
type FindingEvent struct {
	TenantID       string    `ch:"tenant_id"`
	SessionID      [16]byte  `ch:"session_id"`
	TS             time.Time `ch:"ts"`
	EventID        uint64    `ch:"event_id"`
	FindingClass   string    `ch:"finding_class"`
	Detectors      []string  `ch:"detectors"`
	Score          uint8     `ch:"score"`
	SourceKind     uint8     `ch:"source_kind"`
	SourceServer   string    `ch:"source_server"`
	SourceTool     string    `ch:"source_tool"`
	SourceCallHash uint64    `ch:"source_call_hash"`
	ContentFP      uint64    `ch:"content_fp"`
	AgentID        string    `ch:"agent_id"`
	TraceID        [16]byte  `ch:"trace_id"`
}

// IDGen produces time-ordered 64-bit ids: 41 bits of milliseconds since the
// epoch of 2026-01-01, 10 bits of node, 12 bits of sequence. Ids from one node
// are strictly increasing; collisions across nodes need distinct node numbers.
type IDGen struct {
	node uint64
	last atomic.Uint64 // ms<<12 | seq
	now  func() time.Time
}

var idEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// NewIDGen returns a generator for node (0..1023).
func NewIDGen(node uint16) *IDGen { return &IDGen{node: uint64(node & 0x3FF), now: time.Now} }

// Next returns the next id.
func (g *IDGen) Next() uint64 {
	for {
		ms := uint64(g.now().Sub(idEpoch).Milliseconds())
		prev := g.last.Load()
		next := ms << 12
		if next <= prev { // same millisecond (or the clock stepped back): continue the sequence
			next = prev + 1
		}
		if g.last.CompareAndSwap(prev, next) {
			return (next>>12)<<22 | g.node<<12 | next&0xFFF
		}
	}
}
