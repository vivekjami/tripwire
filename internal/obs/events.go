package obs

import "time"

// RequestEvent is one row of the per-request operational ledger
// (tw.request_events, ARCHITECTURE §10.6). Field names and widths mirror the
// ClickHouse DDL so the Phase 1/4 writer is a mechanical mapping. In Phase 0
// the struct exists and is exercised by tests; nothing persists it yet.
//
// It deliberately contains no payload, value or fingerprint fields: only
// classes, counts, sizes and timings (ARCHITECTURE T12/T14).
type RequestEvent struct {
	TenantID  string
	SessionID [16]byte // UInt128
	TS        time.Time
	EventID   uint64 // time-ordered: 41b ms | 10b node | 12b seq
	AgentID   string
	Surface   Surface
	Method    string
	Stream    bool
	Status    uint16

	BytesIn   uint32
	BytesOut  uint32
	EventsOut uint32

	// Timings in microseconds (monotonic clock deltas).
	TAuthnUS, TScanUS, TPolicyUS, TRewriteUS, TTotalAddedUS uint32
	HoldbackP99US                                           uint32

	NDetect, NActions uint16
	StageMask         uint8 // bit0 stage1, bit1 stage2, bit2 stage3
	Degraded          bool
	SinkContextCount  uint32
	TraceID           [16]byte
}

// Surface identifies the protocol surface of a request.
type Surface uint8

const (
	SurfaceChat Surface = iota + 1
	SurfaceResponses
	SurfaceMCP
)

func (s Surface) String() string {
	switch s {
	case SurfaceChat:
		return "chat"
	case SurfaceResponses:
		return "responses"
	case SurfaceMCP:
		return "mcp"
	}
	return "unknown"
}

// StageTimer records stage durations without allocating: a fixed array indexed
// by Stage, filled from a monotonic clock supplied by the caller (so tests can
// inject a fake). The Phase 1 gateway wires this into RequestEvent.
type StageTimer struct {
	now   func() int64
	start int64
	last  int64
	dur   [numStages]int64
}

// Stage names a timed step of the request path (ARCHITECTURE §1.4).
type Stage uint8

const (
	StageAuthn Stage = iota
	StageScan
	StageDetect
	StagePolicy
	StageRewrite
	StageForward
	numStages
)

// NewStageTimer starts timing now. now returns monotonic nanoseconds.
func NewStageTimer(now func() int64) StageTimer {
	t := now()
	return StageTimer{now: now, start: t, last: t}
}

// Mark attributes the time since the previous Mark (or start) to stage s.
func (t *StageTimer) Mark(s Stage) {
	n := t.now()
	t.dur[s] += n - t.last
	t.last = n
}

// DurationUS returns the accumulated microseconds for a stage.
func (t *StageTimer) DurationUS(s Stage) uint32 { return uint32(t.dur[s] / 1000) }

// TotalUS returns microseconds since the timer started.
func (t *StageTimer) TotalUS() uint32 { return uint32((t.last - t.start) / 1000) }
