// Package upstream is the gateway's client for provider endpoints: pooled
// h1/h2 transports, deadlines, credential brokering and header hygiene
// (ARCHITECTURE §8.3, ADR-17, ADR-19). The agent's credential never reaches an
// upstream: outbound headers are built from an allow-list, and the upstream
// credential is injected here.
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vivekjami/tripwire/internal/config"
)

// Client talks to one configured upstream.
type Client struct {
	Name    string
	base    *url.URL
	rt      *http.Transport
	cred    atomic.Pointer[string]
	credF   string
	timeout time.Duration
	retries int
	ua      string
}

// New builds a client from config. The credential file (if any) is read now and
// on Refresh.
func New(name string, c config.Upstream, version string) (*Client, error) {
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("upstream %s: bad url %q", name, c.URL)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("upstream %s: url must not carry userinfo, query or fragment", name)
	}
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		DialContext:           d.DialContext,
		MaxIdleConns:          0,
		MaxIdleConnsPerHost:   4096,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 0,    // governed by the request context deadline
		DisableCompression:    true, // we ask for identity and never decode upstream bodies
		ForceAttemptHTTP2:     u.Scheme == "https",
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ReadBufferSize:        16 << 10, WriteBufferSize: 4 << 10,
		Proxy: nil, // never honour HTTP(S)_PROXY from the environment
	}
	if c.H2C {
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetUnencryptedHTTP2(true)
		tr.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: 1 << 14}
	}
	t := c.Timeout
	if t == 0 {
		t = 60 * time.Second
	}
	cl := &Client{Name: name, base: u, rt: tr, credF: c.CredentialFile, timeout: t, retries: c.Retries, ua: "tripwire-gateway/" + version}
	if err := cl.Refresh(); err != nil {
		return nil, err
	}
	return cl, nil
}

// Refresh re-reads the credential file.
func (c *Client) Refresh() error {
	if c.credF == "" {
		return nil
	}
	b, err := os.ReadFile(c.credF) //nolint:gosec // operator-supplied secret path
	if err != nil {
		return fmt.Errorf("upstream %s: credential: %w", c.Name, err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" || strings.ContainsAny(s, "\r\n") {
		return fmt.Errorf("upstream %s: credential file is empty or multi-line", c.Name)
	}
	c.cred.Store(&s)
	return nil
}

// Timeout is the non-stream deadline.
func (c *Client) Timeout() time.Duration { return c.timeout }

// Close drops idle connections.
func (c *Client) Close() { c.rt.CloseIdleConnections() }

var traceparentRE = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

// Request describes one outbound call.
type Request struct {
	Method      string
	Path        string // origin-form path beginning with a single '/'
	Body        []byte
	ContentType string
	RequestID   string
	Traceparent string // propagated only if it is a well-formed W3C traceparent
	Stream      bool
}

// ErrNotSent wraps failures that happened before any request byte could have
// reached the upstream (so a retry cannot duplicate side effects).
var ErrNotSent = errors.New("upstream: request not sent")

// Do sends the request and returns the response (caller closes the body).
// Retries apply only to ErrNotSent failures, and to GET requests (idempotent).
func (c *Client) Do(ctx context.Context, r Request) (*http.Response, error) {
	if r.Path == "" || r.Path[0] != '/' || strings.HasPrefix(r.Path, "//") || strings.ContainsAny(r.Path, "\r\n \\?#") {
		return nil, fmt.Errorf("upstream: refusing path %q", r.Path)
	}
	target := *c.base
	target.Path = strings.TrimRight(c.base.Path, "/") + r.Path
	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		var body *bytes.Reader
		if r.Body != nil {
			body = bytes.NewReader(r.Body)
		}
		var req *http.Request
		var err error
		if body != nil {
			req, err = http.NewRequestWithContext(ctx, r.Method, target.String(), body)
		} else {
			req, err = http.NewRequestWithContext(ctx, r.Method, target.String(), nil)
		}
		if err != nil {
			return nil, err
		}
		c.headers(req, r)
		resp, err := c.rt.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if ctx.Err() != nil || !(notSent(err) || r.Method == http.MethodGet) {
			break
		}
	}
	if notSent(lastErr) {
		return nil, fmt.Errorf("%w: %v", ErrNotSent, lastErr)
	}
	return nil, lastErr
}

// notSent reports dial-level failures: nothing was written to a connection.
func notSent(err error) bool {
	var oe *net.OpError
	return errors.As(err, &oe) && oe.Op == "dial"
}

// headers builds the outbound header set from scratch (allow-list). Nothing
// from the inbound request is copied except the values passed in r.
func (c *Client) headers(req *http.Request, r Request) {
	h := req.Header
	h.Set("User-Agent", c.ua)
	h.Set("Accept-Encoding", "identity") // ADR-19: we never decode upstream bodies
	if r.ContentType != "" {
		h.Set("Content-Type", r.ContentType)
	}
	if r.Stream {
		h.Set("Accept", "text/event-stream")
	} else {
		h.Set("Accept", "application/json")
	}
	if r.RequestID != "" {
		h.Set("X-Request-Id", r.RequestID)
	}
	if traceparentRE.MatchString(r.Traceparent) {
		h.Set("Traceparent", r.Traceparent)
	}
	if cred := c.cred.Load(); cred != nil {
		h.Set("Authorization", "Bearer "+*cred)
	}
}
