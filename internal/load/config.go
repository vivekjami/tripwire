// Package load implements twload: an OPEN-LOOP load generator.
//
// Open loop means requests are issued on a pre-computed arrival schedule
// regardless of how fast earlier requests complete, and every latency is
// measured from the request's INTENDED send time, not from when the generator
// got around to sending it. A closed-loop generator (or an open-loop one that
// stamps latency from actual send time) silently drops the samples that
// would have shown a stall: coordinated omission. The self-validation tests
// in this package prove the generator does not suffer from it.
package load

import (
	"time"

	"github.com/vivekjami/tripwire/internal/mock"
	"github.com/vivekjami/tripwire/internal/trace"
)

// Config configures a run.
type Config struct {
	RunID  string
	OutDir string // results/<run-id>
	Target string // base URL, e.g. http://127.0.0.1:9000
	Mode   string // http | mcp | connections | lineage
	H2C    bool   // speak HTTP/2 cleartext to Target
	TLSCA  string // PEM roots to trust for an https Target (verification is never disabled)
	H2TLS  bool   // https Target: negotiate HTTP/2 via ALPN (default HTTP/1.1 over TLS)

	// Arrival process
	Rate     float64
	Duration time.Duration // measurement window
	Warmup   time.Duration // run first, discarded
	Arrivals trace.Arrivals
	Seed     int64

	SpinMargin     time.Duration // dispatcher spins this long before each arrival (see waitUntil)
	MaxInflight    int           // concurrency cap; exceeding it makes the generator fall behind (visible as dispatch lag)
	RequestTimeout time.Duration // per request
	DrainTimeout   time.Duration // wait for in-flight after the window

	// HTTP workload
	Surface    string // chat | responses
	StreamFrac float64
	Events     int
	Gap        string
	Chunk      string
	Inject     []mock.Inject
	InjectFrac float64
	Fault      *mock.Fault
	FaultFrac  float64

	// MCP workload
	MCPVersion      string // 2026-07-28 | 2025-11-25
	MCPTool         string
	MCPMismatchFrac float64 // fraction sent with a deliberately wrong Mcp-Name (expect rejection)

	// Idle connection storm (any mode); Mode=connections holds them with no traffic.
	IdleConns int

	// Joining with the mock
	GTLog       string  // ground-truth JSONL written by twmock
	EmitLog     string  // emit-timestamp CSV written by twmock
	EmitSample  float64 // must equal twmock --emit-sample
	CheckSample float64 // fraction of streams fully parsed and ground-truth checked

	// Self-measurement of the system under test
	SUTMetrics string // Prometheus text endpoint of the SUT (process_cpu_seconds_total)
	MockStats  string // twmock /_tw/stats URL
}

func (c *Config) applyDefaults() {
	if c.Mode == "" {
		c.Mode = "http"
	}
	if c.Surface == "" {
		c.Surface = "chat"
	}
	if c.SpinMargin == 0 {
		c.SpinMargin = 1500 * time.Microsecond
	}
	if c.MaxInflight == 0 {
		c.MaxInflight = 200_000
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = 60 * time.Second
	}
	if c.DrainTimeout == 0 {
		c.DrainTimeout = 30 * time.Second
	}
	if c.Events == 0 {
		c.Events = 64
	}
	if c.Gap == "" {
		c.Gap = "const:20ms"
	}
	if c.Chunk == "" {
		c.Chunk = "token"
	}
	if c.MCPVersion == "" {
		c.MCPVersion = "2025-11-25"
	}
	if c.MCPTool == "" {
		c.MCPTool = "get_customer"
	}
	if c.RunID == "" {
		c.RunID = time.Now().UTC().Format("20060102T150405Z")
	}
}
