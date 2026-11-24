package gateway

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vivekjami/tripwire/internal/auth"
	"github.com/vivekjami/tripwire/internal/clock"
	"github.com/vivekjami/tripwire/internal/lineage"
	"github.com/vivekjami/tripwire/internal/obs"
)

// reqState is the per-request measurement record (WP1.7). It lives in the
// request context, is written only by the goroutine serving the request, and
// becomes one lineage request_events row when the request finishes. It holds
// sizes, counts and timings only: never payload bytes or detected values.
type reqState struct {
	timer obs.StageTimer
	start time.Time

	agent   *auth.Agent
	surface obs.Surface
	method  string
	stream  bool

	bytesIn   uint32
	eventsOut uint32
	// Stage attribution (ns). authn/scan come from the StageTimer; upstream is
	// time spent waiting for the provider; addedStream sums, per streamed
	// event, the time between "event fully received" and "flushed to client".
	upstreamNS  int64
	addedStream int64
	holdMaxUS   uint32
}

const reqStateKey ctxKey = 100

func newReqState() *reqState {
	return &reqState{timer: obs.NewStageTimer(clock.Now), start: time.Now(), surface: obs.SurfaceChat}
}

func stateFrom(ctx context.Context) *reqState {
	st, _ := ctx.Value(reqStateKey).(*reqState)
	return st
}

// markUpstream attributes the time since the last mark to waiting on the
// provider (stage "forward").
func (st *reqState) markUpstream() {
	if st == nil {
		return
	}
	before := st.timer.DurationUS(obs.StageForward)
	st.timer.Mark(obs.StageForward)
	st.upstreamNS += int64(st.timer.DurationUS(obs.StageForward)-before) * 1000
}

// addedUS is what the gateway itself added to this request: everything except
// time waiting for the provider. For streams the per-event sum is used because
// total wall time is dominated by the model's own generation time.
func (st *reqState) addedUS() uint32 {
	if st.stream {
		return st.timer.DurationUS(obs.StageAuthn) + st.timer.DurationUS(obs.StageScan) + uint32(st.addedStream/1000)
	}
	total := int64(st.timer.TotalUS())
	if v := total - st.upstreamNS/1000; v > 0 {
		return uint32(v)
	}
	return 0
}

// serverTiming renders the Server-Timing header (admin agents only).
func (st *reqState) serverTiming() string {
	ms := func(us uint32) string { return fmt.Sprintf("%.3f", float64(us)/1000) }
	return "authn;dur=" + ms(st.timer.DurationUS(obs.StageAuthn)) +
		", scan;dur=" + ms(st.timer.DurationUS(obs.StageScan)) +
		", upstream;dur=" + ms(uint32(st.upstreamNS/1000)) +
		", gateway;dur=" + ms(st.addedUS())
}

func setServerTiming(w http.ResponseWriter, st *reqState) {
	if st != nil && st.agent != nil && st.agent.Admin {
		w.Header().Set("Server-Timing", st.serverTiming())
	}
}

// emit turns the finished request into a lineage event.
func (s *Server) emit(st *reqState, status int, bytesOut uint32, traceparent string) {
	if st == nil || st.agent == nil || s.lin == nil {
		return
	}
	e := lineage.NewEvent(lineage.KindRequest)
	r := &e.Request
	r.TenantID, r.AgentID = st.agent.Tenant, st.agent.ID
	r.TS, r.EventID = st.start, s.ids.Next()
	r.Surface, r.Method, r.Stream, r.Status = st.surface, st.method, st.stream, uint16(status)
	r.BytesIn, r.BytesOut, r.EventsOut = st.bytesIn, bytesOut, st.eventsOut
	r.TAuthnUS = st.timer.DurationUS(obs.StageAuthn)
	r.TScanUS = st.timer.DurationUS(obs.StageScan)
	r.TPolicyUS, r.TRewriteUS = st.timer.DurationUS(obs.StagePolicy), st.timer.DurationUS(obs.StageRewrite)
	r.TTotalAddedUS = st.addedUS()
	r.HoldbackP99US = st.holdMaxUS
	r.TraceID = traceIDFrom(traceparent)
	s.lin.Emit(e)
}

// traceIDFrom extracts the 16-byte trace id of a well-formed W3C traceparent,
// or mints a random one.
func traceIDFrom(tp string) (id [16]byte) {
	if len(tp) == 55 && strings.HasPrefix(tp, "00-") && tp[35] == '-' && tp[52] == '-' {
		ok := true
		for i := 0; i < 16; i++ {
			hi, lo := unhex(tp[3+2*i]), unhex(tp[4+2*i])
			if hi < 0 || lo < 0 {
				ok = false
				break
			}
			id[i] = byte(hi<<4 | lo)
		}
		if ok {
			return id
		}
	}
	_, _ = rand.Read(id[:])
	return id
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return -1
}
