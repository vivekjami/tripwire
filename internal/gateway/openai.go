package gateway

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vivekjami/tripwire/internal/auth"
	"github.com/vivekjami/tripwire/internal/jsonscan"
	"github.com/vivekjami/tripwire/internal/openai"
	"github.com/vivekjami/tripwire/internal/upstream"
)

type route struct {
	glob auth.Glob
	up   *upstream.Client
}

// chatAPI serves the OpenAI-compatible surface. Phase 1 behaviour: parse
// strictly, forward only validated bytes, inspect nothing (NoopWalker).
type chatAPI struct {
	s      *Server
	routes []route
	ups    []*upstream.Client
	walker openai.Walker
	lim    jsonscan.Limits

	swalker StreamWalker
	sm      *streamMetrics

	upReqs *prometheus.CounterVec
	upDur  *prometheus.HistogramVec
}

func (s *Server) newChatAPI() (*chatAPI, error) {
	a := &chatAPI{s: s, walker: openai.NoopWalker{}, swalker: noopStreamWalker{}, lim: jsonscan.DefaultLimits()}
	a.lim.MaxBytes = int(s.cfg.Limits.BodyBytes)
	byName := map[string]*upstream.Client{}
	for name, uc := range s.cfg.Upstreams {
		c, err := upstream.New(name, uc, s.opt.Version)
		if err != nil {
			return nil, err
		}
		byName[name] = c
		a.ups = append(a.ups, c)
	}
	sort.Slice(a.ups, func(i, j int) bool { return a.ups[i].Name < a.ups[j].Name })
	for _, r := range s.cfg.Routes {
		a.routes = append(a.routes, route{glob: auth.CompileGlob(r.Model), up: byName[r.Upstream]})
	}
	a.upReqs = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tw_upstream_requests_total", Help: "Upstream calls by upstream and status class."}, []string{"upstream", "class"})
	a.upDur = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "tw_upstream_seconds", Help: "Upstream call duration (non-stream: whole response).",
		NativeHistogramBucketFactor: 1.1, NativeHistogramMaxBucketNumber: 100, Buckets: prometheus.ExponentialBuckets(0.001, 2, 16)}, []string{"upstream"})
	s.opt.Metrics.MustRegister(a.upReqs, a.upDur)
	a.sm = newStreamMetrics(a)
	return a, nil
}

// Handler returns the data-plane mux.
func (a *chatAPI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", a.method(http.MethodPost, a.chat))
	mux.HandleFunc("/v1/models", a.method(http.MethodGet, a.models))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeErr(w, http.StatusNotFound, "invalid_request_error", "not_found", "unknown route")
	})
	return mux
}

func (a *chatAPI) method(m string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != m {
			w.Header().Set("Allow", m)
			writeErr(w, http.StatusMethodNotAllowed, "invalid_request_error", "method_not_allowed", "method not allowed")
			return
		}
		h(w, r)
	}
}

// resolve maps a model to its upstream for this agent. Unknown models and
// models outside the agent's scope are indistinguishable (same status, body).
func (a *chatAPI) resolve(ag *auth.Agent, model string) *upstream.Client {
	if !ag.ModelAllowed(model) {
		return nil
	}
	for _, r := range a.routes {
		if r.glob.Match(model) {
			return r.up
		}
	}
	return nil
}

func modelNotFound(w http.ResponseWriter) {
	writeErr(w, http.StatusNotFound, "invalid_request_error", "model_not_found", "the requested model does not exist or is not available to this agent")
}

// readBody reads the request body with content-encoding handling and the
// decompression-bomb defence (size cap AND ratio cap).
func (a *chatAPI) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(r.Body) // r.Body is already capped by limitMW
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "invalid_request_error", "request_too_large", "request body too large")
		} else {
			writeErr(w, http.StatusBadRequest, "invalid_request_error", "bad_body", "could not read request body")
		}
		return nil, false
	}
	enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	switch enc {
	case "", "identity":
		return body, true
	case "gzip":
		max := int64(a.s.cfg.Limits.DecompressRatio)*int64(len(body)) + 1024
		if limit := a.s.cfg.Limits.BodyBytes; max > limit {
			max = limit
		}
		if ag := AgentFrom(r.Context()); ag != nil && ag.MaxBody > 0 && max > ag.MaxBody {
			max = ag.MaxBody
		}
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request_error", "bad_encoding", "invalid gzip body")
			return nil, false
		}
		defer zr.Close()
		out, err := io.ReadAll(io.LimitReader(zr, max+1))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request_error", "bad_encoding", "invalid gzip body")
			return nil, false
		}
		if int64(len(out)) > max {
			writeErr(w, http.StatusRequestEntityTooLarge, "invalid_request_error", "request_too_large", "decompressed body too large")
			return nil, false
		}
		return out, true
	}
	writeErr(w, http.StatusUnsupportedMediaType, "invalid_request_error", "unsupported_encoding", "unsupported Content-Encoding")
	return nil, false
}

func jsonContentType(h http.Header) bool {
	vals := h.Values("Content-Type")
	if len(vals) != 1 {
		return false
	}
	mt, params, err := mime.ParseMediaType(vals[0])
	if err != nil || mt != "application/json" {
		return false
	}
	if cs, ok := params["charset"]; ok && !strings.EqualFold(cs, "utf-8") {
		return false
	}
	return true
}

func (a *chatAPI) chat(w http.ResponseWriter, r *http.Request) {
	ag := AgentFrom(r.Context())
	if !jsonContentType(r.Header) {
		writeErr(w, http.StatusUnsupportedMediaType, "invalid_request_error", "unsupported_media_type", "Content-Type must be application/json")
		return
	}
	body, ok := a.readBody(w, r)
	if !ok {
		return
	}
	req, err := openai.ParseChatRequest(body, a.lim)
	if err != nil {
		var ve *openai.ValidationError
		if errors.As(err, &ve) {
			writeErr(w, http.StatusBadRequest, "invalid_request_error", ve.Code, ve.Msg)
		} else {
			writeErr(w, http.StatusBadRequest, "invalid_request_error", "invalid_request", "invalid request")
		}
		return
	}
	up := a.resolve(ag, req.Model)
	if up == nil {
		modelNotFound(w)
		return
	}
	if err := openai.WalkRequest(req, a.walker); err != nil { // Phase 1: never errors
		writeErr(w, http.StatusBadRequest, "invalid_request_error", "blocked", "request blocked by policy")
		return
	}
	if req.Stream {
		a.stream(w, r, ag, up, req)
		return
	}
	a.forwardJSON(w, r, up, req)
}

func classOf(code int) string { return strconv.Itoa(code/100) + "xx" }

func (a *chatAPI) forwardJSON(w http.ResponseWriter, r *http.Request, up *upstream.Client, req *openai.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), up.Timeout())
	defer cancel()
	start := time.Now()
	resp, err := up.Do(ctx, upstream.Request{
		Method: http.MethodPost, Path: "/v1/chat/completions", Body: req.Doc, ContentType: "application/json",
		RequestID: RequestIDFrom(r.Context()), Traceparent: r.Header.Get("Traceparent"),
	})
	if err != nil {
		a.upReqs.WithLabelValues(up.Name, "error").Inc()
		upstreamFailure(w, ctx, err)
		return
	}
	defer resp.Body.Close()
	a.relayBounded(w, ctx, up, resp, start)
}

// relayBounded forwards a bounded, validated, non-stream upstream response (also
// used for error bodies of streaming calls).
func (a *chatAPI) relayBounded(w http.ResponseWriter, ctx context.Context, up *upstream.Client, resp *http.Response, start time.Time) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, a.s.cfg.Limits.ResponseBytes+1))
	a.upDur.WithLabelValues(up.Name).Observe(time.Since(start).Seconds())
	a.upReqs.WithLabelValues(up.Name, classOf(resp.StatusCode)).Inc()
	if err != nil {
		upstreamFailure(w, ctx, err)
		return
	}
	if int64(len(raw)) > a.s.cfg.Limits.ResponseBytes {
		writeErr(w, http.StatusBadGateway, "server_error", "upstream_response_too_large", "upstream response too large")
		return
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// The gateway's upstream credential failed; that is not the agent's fault
		// and must not look like the agent's own authentication failing.
		writeErr(w, http.StatusBadGateway, "server_error", "upstream_auth_error", "upstream rejected the gateway's credentials")
		return
	}
	if !jsonContentType(resp.Header) && !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "application/json") {
		writeErr(w, http.StatusBadGateway, "server_error", "bad_upstream_response", "upstream returned a non-JSON response")
		return
	}
	if resp.StatusCode/100 == 2 {
		if err := openai.WalkResponse(raw, a.lim, a.walker); err != nil {
			if errors.Is(err, openai.ErrBadResponse) {
				writeErr(w, http.StatusBadGateway, "server_error", "bad_upstream_response", "upstream returned a malformed response")
			} else {
				writeErr(w, http.StatusBadGateway, "server_error", "blocked", "response blocked by policy")
			}
			return
		}
	} else if _, err := jsonscan.Validate(raw, a.lim); err != nil {
		writeErr(w, http.StatusBadGateway, "server_error", "bad_upstream_response", "upstream returned a malformed error")
		return
	}
	writeJSONBytes(w, resp.StatusCode, raw, resp.Header.Get("Retry-After"))
}

// writeJSONBytes writes a JSON body with a Content-Length recomputed from the
// bytes actually written (the response path will rewrite bodies from Phase 2:
// the length must always describe what is sent, never what the upstream sent).
func writeJSONBytes(w http.ResponseWriter, status int, b []byte, retryAfter string) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", strconv.Itoa(len(b)))
	if retryAfter != "" && len(retryAfter) < 16 && strings.Trim(retryAfter, "0123456789") == "" {
		h.Set("Retry-After", retryAfter)
	}
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func upstreamFailure(w http.ResponseWriter, ctx context.Context, err error) {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		writeErr(w, http.StatusGatewayTimeout, "server_error", "upstream_timeout", "upstream timed out")
	case errors.Is(err, upstream.ErrNotSent):
		writeErr(w, http.StatusBadGateway, "server_error", "upstream_unavailable", "upstream unavailable")
	default:
		writeErr(w, http.StatusBadGateway, "server_error", "upstream_error", "upstream error")
	}
}

// models answers GET /v1/models with the union of the models the routed
// upstreams list, filtered to the agent's scope and to routed models.
func (a *chatAPI) models(w http.ResponseWriter, r *http.Request) {
	ag := AgentFrom(r.Context())
	seen := map[string]bool{}
	var out []json.RawMessage
	ok := 0
	failed := 0
	for _, up := range a.ups {
		ctx, cancel := context.WithTimeout(r.Context(), up.Timeout())
		resp, err := up.Do(ctx, upstream.Request{Method: http.MethodGet, Path: "/v1/models", RequestID: RequestIDFrom(r.Context())})
		if err != nil {
			cancel()
			failed++
			continue
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, a.s.cfg.Limits.ResponseBytes+1))
		resp.Body.Close()
		cancel()
		if rerr != nil || resp.StatusCode != 200 || int64(len(raw)) > a.s.cfg.Limits.ResponseBytes {
			failed++
			continue
		}
		root, verr := jsonscan.Validate(raw, a.lim)
		if verr != nil {
			failed++
			continue
		}
		ok++
		data, has := jsonscan.Lookup(raw, root, "data")
		if !has {
			continue
		}
		jsonscan.Elems(raw, data, func(_ int, m jsonscan.Span) bool {
			idSpan, has := jsonscan.Lookup(raw, m, "id")
			id, isStr := jsonscan.StringValue(raw, idSpan)
			if !has || !isStr || seen[id] {
				return true
			}
			// the id must be routed to THIS upstream and be in the agent's scope
			if a.resolve(ag, id) != up {
				return true
			}
			seen[id] = true
			out = append(out, json.RawMessage(append([]byte(nil), raw[m.Start:m.End]...)))
			return true
		})
	}
	if ok == 0 && failed > 0 {
		writeErr(w, http.StatusBadGateway, "server_error", "upstream_unavailable", "upstream unavailable")
		return
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	if out == nil {
		out = []json.RawMessage{}
	}
	b, _ := json.Marshal(struct {
		Object string            `json:"object"`
		Data   []json.RawMessage `json:"data"`
	}{"list", out})
	writeJSONBytes(w, http.StatusOK, b, "")
}
