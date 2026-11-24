// Package config is the gateway's strict YAML configuration (schema v0.9).
//
// Rules (IMPLEMENTATION_PLAN WP1.1, ARCHITECTURE §14.2): unknown fields are
// rejected; defaults are explicit; every validation error carries the YAML line
// it refers to; every limit has a default and is enforced.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SchemaVersion is the config schema this build understands.
const SchemaVersion = "0.9"

// Config is the whole gateway configuration.
type Config struct {
	Version   string              `yaml:"version"`
	Listen    Listen              `yaml:"listen"`
	Limits    Limits              `yaml:"limits"`
	Runtime   Runtime             `yaml:"runtime"`
	Upstreams map[string]Upstream `yaml:"upstreams"`
	Routes    []Route             `yaml:"routes"`
	Auth      Auth                `yaml:"auth"`
	Agents    []Agent             `yaml:"agents"`
}

// Listen configures the data and admin listeners.
type Listen struct {
	Data  string `yaml:"data"`  // data plane address
	Admin string `yaml:"admin"` // admin plane address (/metrics, pprof, health); loopback by default
	H2C   bool   `yaml:"h2c"`   // accept cleartext HTTP/2 (prior knowledge) on the data listener
	TLS   TLS    `yaml:"tls"`
}

// TLS configures server certificates (hot-reloaded) for a listener.
type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Limits are the edge limits (ARCHITECTURE §14.2). Zero is never "unlimited"
// except where stated.
type Limits struct {
	HeaderBytes       int           `yaml:"header_bytes"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	BodyBytes         int64         `yaml:"body_bytes"`
	ResponseBytes     int64         `yaml:"response_bytes"`   // non-stream upstream response cap
	DecompressRatio   int           `yaml:"decompress_ratio"` // max decompressed/compressed request size
	WriteDeadline     time.Duration `yaml:"write_deadline"`
	DrainTimeout      time.Duration `yaml:"drain_timeout"`
	MaxConnections    int           `yaml:"max_connections"` // 0 = no connection cap
	GlobalInflight    int64         `yaml:"global_inflight"` // requests; excess is shed with 429
}

// Runtime tunes the Go runtime.
type Runtime struct {
	GOMAXPROCS int    `yaml:"gomaxprocs"` // 0 = leave to the runtime
	MemLimit   string `yaml:"mem_limit"`  // e.g. "6GiB"; "" = leave GOMEMLIMIT alone
}

// Upstream is a provider the gateway forwards to.
type Upstream struct {
	URL            string        `yaml:"url"`
	CredentialFile string        `yaml:"credential_file"` // file holding the upstream bearer token; never the agent's
	Timeout        time.Duration `yaml:"timeout"`         // non-stream request deadline (default 60s)
	H2C            bool          `yaml:"h2c"`             // speak cleartext HTTP/2 to an http:// upstream
	Retries        int           `yaml:"retries"`         // retries (0-3) of requests that provably never reached the upstream; 0 = none
}

// Route sends requests for models matching a glob to a named upstream. The first
// matching route wins; a model with no route does not exist, as far as any
// agent can tell.
type Route struct {
	Model    string `yaml:"model"`
	Upstream string `yaml:"upstream"`
}

// Auth configures authentication sources.
type Auth struct {
	PepperFile string   `yaml:"pepper_file"` // file with the API-key hashing pepper (>= 16 bytes)
	APIKeys    []APIKey `yaml:"api_keys"`
}

// APIKey is one stored API key: only a peppered SHA-256 is configured.
type APIKey struct {
	Agent     string    `yaml:"agent"`
	SHA256    string    `yaml:"sha256"`     // hex of SHA-256(pepper || key)
	NotAfter  time.Time `yaml:"not_after"`  // rotation overlap: old key stops working at this time (zero = never)
	NotBefore time.Time `yaml:"not_before"` // new key starts working at this time (zero = immediately)
}

// Agent scopes one agent.
type Agent struct {
	ID     string      `yaml:"id"`
	Tenant string      `yaml:"tenant"`
	Models []string    `yaml:"models"` // glob list; empty = no models allowed
	Limits AgentLimits `yaml:"limits"`
}

// AgentLimits are per-agent rate and concurrency limits.
type AgentLimits struct {
	RPS               float64 `yaml:"rps"`
	Burst             int     `yaml:"burst"`
	ConcurrentStreams int     `yaml:"concurrent_streams"`
	MaxBody           int64   `yaml:"max_body"`
}

// Defaults returns the default configuration (ARCHITECTURE §14.2).
func Defaults() Config {
	return Config{
		Version: SchemaVersion,
		Listen:  Listen{Data: "127.0.0.1:8080", Admin: "127.0.0.1:9090"},
		Limits: Limits{
			HeaderBytes: 32 << 10, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 120 * time.Second,
			BodyBytes: 8 << 20, ResponseBytes: 16 << 20, DecompressRatio: 20, WriteDeadline: 10 * time.Second, DrainTimeout: 30 * time.Second,
			GlobalInflight: 60000,
		},
	}
}

// Error is one problem with a config file.
type Error struct {
	Line int    // 1-based; 0 if unknown
	Path string // dotted path, e.g. agents[1].limits.rps
	Msg  string
}

func (e Error) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s: %s", e.Line, e.Path, e.Msg)
	}
	return fmt.Sprintf("%s: %s", e.Path, e.Msg)
}

// Errors is a list of problems; Load returns all of them at once.
type Errors []Error

func (es Errors) Error() string {
	var b strings.Builder
	for i, e := range es {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(e.Error())
	}
	return b.String()
}

// LoadFile reads, strictly decodes, defaults and validates a config file.
func LoadFile(path string) (*Config, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied config path
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return Parse(b)
}

// Parse strictly decodes, defaults and validates config bytes.
func Parse(b []byte) (*Config, error) {
	cfg := Defaults()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true) // unknown fields are errors
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, wrapYAML(err)
	}
	var root yaml.Node
	_ = yaml.Unmarshal(b, &root) // cannot fail after a successful strict decode
	if errs := cfg.validate(&root); len(errs) > 0 {
		return nil, errs
	}
	return &cfg, nil
}

// wrapYAML turns yaml.v3 errors (which already say "line N:") into Errors.
func wrapYAML(err error) error {
	var te *yaml.TypeError
	if errors.As(err, &te) {
		out := make(Errors, 0, len(te.Errors))
		for _, m := range te.Errors {
			e := Error{Path: "yaml", Msg: m}
			if rest, ok := strings.CutPrefix(m, "line "); ok {
				var n int
				if _, serr := fmt.Sscanf(rest, "%d:", &n); serr == nil {
					e.Line = n
					if _, after, ok := strings.Cut(rest, ": "); ok {
						e.Msg = after
					}
				}
			}
			out = append(out, e)
		}
		return out
	}
	return Errors{{Path: "yaml", Msg: err.Error()}}
}

// lineOf finds the line of a dotted/indexed path in the YAML tree (0 if absent).
func lineOf(root *yaml.Node, path ...any) int {
	n := root
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	last := n.Line
	for _, p := range path {
		switch k := p.(type) {
		case string:
			if n.Kind != yaml.MappingNode {
				return last
			}
			found := false
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Value == k {
					last, n, found = n.Content[i].Line, n.Content[i+1], true
					break
				}
			}
			if !found {
				return last
			}
		case int:
			if n.Kind != yaml.SequenceNode || k >= len(n.Content) {
				return last
			}
			n = n.Content[k]
			last = n.Line
		}
	}
	return last
}

func (c *Config) validate(root *yaml.Node) Errors {
	var errs Errors
	add := func(path string, msg string, loc ...any) {
		errs = append(errs, Error{Line: lineOf(root, loc...), Path: path, Msg: msg})
	}
	if c.Version != SchemaVersion {
		add("version", fmt.Sprintf("unsupported schema version %q (this build understands %q)", c.Version, SchemaVersion), "version")
	}
	if c.Listen.Data == "" {
		add("listen.data", "must be set", "listen", "data")
	}
	if c.Listen.Admin == "" {
		add("listen.admin", "must be set (the admin plane is never served on the data listener)", "listen", "admin")
	}
	if c.Listen.Data != "" && c.Listen.Data == c.Listen.Admin {
		add("listen.admin", "must differ from listen.data", "listen", "admin")
	}
	if (c.Listen.TLS.CertFile == "") != (c.Listen.TLS.KeyFile == "") {
		add("listen.tls", "cert_file and key_file must be set together", "listen", "tls")
	}
	if c.Listen.H2C && c.Listen.TLS.CertFile != "" {
		add("listen.h2c", "h2c is the cleartext listener; with TLS, HTTP/2 is negotiated via ALPN", "listen", "h2c")
	}
	l := &c.Limits
	pos := func(name string, ok bool) {
		if !ok {
			add("limits."+name, "must be > 0", "limits", name)
		}
	}
	pos("header_bytes", l.HeaderBytes > 0)
	pos("read_header_timeout", l.ReadHeaderTimeout > 0)
	pos("idle_timeout", l.IdleTimeout > 0)
	pos("body_bytes", l.BodyBytes > 0)
	pos("response_bytes", l.ResponseBytes > 0)
	pos("decompress_ratio", l.DecompressRatio > 0)
	pos("write_deadline", l.WriteDeadline > 0)
	pos("drain_timeout", l.DrainTimeout > 0)
	pos("global_inflight", l.GlobalInflight > 0)
	if l.MaxConnections < 0 {
		add("limits.max_connections", "must be >= 0", "limits", "max_connections")
	}
	if c.Runtime.GOMAXPROCS < 0 {
		add("runtime.gomaxprocs", "must be >= 0", "runtime", "gomaxprocs")
	}
	if c.Runtime.MemLimit != "" {
		if _, err := ParseBytes(c.Runtime.MemLimit); err != nil {
			add("runtime.mem_limit", err.Error(), "runtime", "mem_limit")
		}
	}
	names := make([]string, 0, len(c.Upstreams))
	for n := range c.Upstreams {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		u := c.Upstreams[n]
		if !strings.HasPrefix(u.URL, "http://") && !strings.HasPrefix(u.URL, "https://") {
			add("upstreams."+n+".url", "must be an http:// or https:// base URL", "upstreams", n, "url")
		}
		if u.Timeout < 0 {
			add("upstreams."+n+".timeout", "must be >= 0", "upstreams", n, "timeout")
		}
		if u.Retries < 0 || u.Retries > 3 {
			add("upstreams."+n+".retries", "must be 0-3", "upstreams", n, "retries")
		}
		if u.H2C && !strings.HasPrefix(u.URL, "http://") {
			add("upstreams."+n+".h2c", "h2c requires an http:// URL (https negotiates h2 via ALPN)", "upstreams", n, "h2c")
		}
	}
	for i, r := range c.Routes {
		if r.Model == "" {
			add(fmt.Sprintf("routes[%d].model", i), "must be set", "routes", i, "model")
		}
		if _, ok := c.Upstreams[r.Upstream]; !ok {
			add(fmt.Sprintf("routes[%d].upstream", i), fmt.Sprintf("unknown upstream %q", r.Upstream), "routes", i, "upstream")
		}
	}
	seen := map[string]bool{}
	for i, a := range c.Agents {
		p := fmt.Sprintf("agents[%d]", i)
		if !validID(a.ID) {
			add(p+".id", "must be 1-64 chars of [a-z0-9-] (no underscore: it delimits API keys)", "agents", i, "id")
		} else if seen[a.ID] {
			add(p+".id", fmt.Sprintf("duplicate agent id %q", a.ID), "agents", i, "id")
		}
		seen[a.ID] = true
		if a.Tenant == "" {
			add(p+".tenant", "must be set", "agents", i, "tenant")
		}
		if a.Limits.RPS < 0 || a.Limits.Burst < 0 || a.Limits.ConcurrentStreams < 0 || a.Limits.MaxBody < 0 {
			add(p+".limits", "values must be >= 0 (0 = inherit the global default)", "agents", i, "limits")
		}
		if a.Limits.RPS > 0 && a.Limits.Burst == 0 {
			add(p+".limits.burst", "must be > 0 when rps is set", "agents", i, "limits", "burst")
		}
	}
	for i, k := range c.Auth.APIKeys {
		p := fmt.Sprintf("auth.api_keys[%d]", i)
		if !seen[k.Agent] {
			add(p+".agent", fmt.Sprintf("unknown agent %q", k.Agent), "auth", "api_keys", i, "agent")
		}
		if len(k.SHA256) != 64 || !isHex(k.SHA256) {
			add(p+".sha256", "must be 64 hex characters", "auth", "api_keys", i, "sha256")
		}
		if !k.NotAfter.IsZero() && !k.NotBefore.IsZero() && !k.NotAfter.After(k.NotBefore) {
			add(p+".not_after", "must be after not_before", "auth", "api_keys", i, "not_after")
		}
	}
	if len(c.Auth.APIKeys) > 0 && c.Auth.PepperFile == "" {
		add("auth.pepper_file", "required when api_keys are configured", "auth", "pepper_file")
	}
	return errs
}

func validID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// ParseBytes parses sizes like "512MiB", "6GiB", "1048576".
func ParseBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	units := []struct {
		suf string
		mul int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}}
	mul := int64(1)
	for _, u := range units {
		if rest, ok := strings.CutSuffix(s, u.suf); ok {
			s, mul = strings.TrimSpace(rest), u.mul
			break
		}
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n <= 0 || fmt.Sprint(n) != s {
		return 0, fmt.Errorf("invalid size %q (use e.g. 512MiB, 6GiB)", s)
	}
	return n * mul, nil
}
