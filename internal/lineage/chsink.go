package lineage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/ch-go"
	"github.com/ClickHouse/ch-go/proto"
)

// CHConfig connects to ClickHouse over the native protocol.
//
// STATUS: written against the ch-go API and compile-checked; it has NOT been
// run against a real ClickHouse server in this repository's environment (no
// server was available). The Phase 1 ingest probe (docs/phases/P1.md) is open
// until it is.
type CHConfig struct {
	Addr        string
	Database    string
	User        string
	Password    string
	Compression ch.Compression // ch.CompressionLZ4 recommended; CompressionDisabled on a fast LAN
	Node        string         // node id used in dedup tokens
	Conns       int            // pooled connections (default 2)
}

// CHSink writes request events to tw.request_events as native column blocks.
// Other event kinds arrive with their writers in Phase 4 and are rejected here
// rather than silently dropped.
type CHSink struct {
	cfg  CHConfig
	pool chan *ch.Client
	seq  atomic.Uint64
}

// ErrUnsupportedKind marks an event kind without a writer yet.
var ErrUnsupportedKind = errors.New("lineage: no ClickHouse writer for this event kind yet")

// NewCHSink dials the pool.
func NewCHSink(ctx context.Context, cfg CHConfig) (*CHSink, error) {
	if cfg.Conns == 0 {
		cfg.Conns = 2
	}
	if cfg.Database == "" {
		cfg.Database = "tw"
	}
	s := &CHSink{cfg: cfg, pool: make(chan *ch.Client, cfg.Conns)}
	for i := 0; i < cfg.Conns; i++ {
		c, err := s.dial(ctx)
		if err != nil {
			s.Close()
			return nil, err
		}
		s.pool <- c
	}
	return s, nil
}

func (s *CHSink) dial(ctx context.Context) (*ch.Client, error) {
	return ch.Dial(ctx, ch.Options{Address: s.cfg.Addr, Database: s.cfg.Database, User: s.cfg.User, Password: s.cfg.Password,
		Compression: s.cfg.Compression, DialTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second})
}

// Close closes pooled connections.
func (s *CHSink) Close() error {
	for {
		select {
		case c := <-s.pool:
			_ = c.Close()
		default:
			return nil
		}
	}
}

// requestColumns builds the column set for one batch, positionally matching the DDL.
type requestColumns struct {
	tenant, agent, method                          *proto.ColLowCardinality[string]
	tenantC, agentC                                proto.ColStr
	session                                        proto.ColUInt128
	ts                                             *proto.ColDateTime64
	eventID                                        proto.ColUInt64
	surface                                        proto.ColEnum
	stream                                         proto.ColUInt8
	status                                         proto.ColUInt16
	bytesIn, bytesOut, eventsOut                   proto.ColUInt32
	tAuthn, tScan, tPolicy, tRewrite, tTotal, hold proto.ColUInt32
	nDetect, nActions                              proto.ColUInt16
	stageMask, degraded                            proto.ColUInt8
	sinkCtx                                        proto.ColUInt32
	trace                                          proto.ColFixedStr
}

func newRequestColumns() *requestColumns {
	c := &requestColumns{ts: new(proto.ColDateTime64).WithPrecision(proto.PrecisionMilli), trace: proto.ColFixedStr{Size: 16}}
	c.tenant, c.agent, c.method = c.tenantC.LowCardinality(), c.agentC.LowCardinality(), (&proto.ColStr{}).LowCardinality()
	return c
}

func (c *requestColumns) input() proto.Input {
	return proto.Input{
		{Name: "tenant_id", Data: c.tenant}, {Name: "session_id", Data: &c.session}, {Name: "ts", Data: c.ts}, {Name: "event_id", Data: &c.eventID},
		{Name: "agent_id", Data: c.agent}, {Name: "surface", Data: &c.surface}, {Name: "method", Data: c.method},
		{Name: "stream", Data: &c.stream}, {Name: "status", Data: &c.status},
		{Name: "bytes_in", Data: &c.bytesIn}, {Name: "bytes_out", Data: &c.bytesOut}, {Name: "events_out", Data: &c.eventsOut},
		{Name: "t_authn_us", Data: &c.tAuthn}, {Name: "t_scan_us", Data: &c.tScan}, {Name: "t_policy_us", Data: &c.tPolicy},
		{Name: "t_rewrite_us", Data: &c.tRewrite}, {Name: "t_total_added_us", Data: &c.tTotal}, {Name: "holdback_p99_us", Data: &c.hold},
		{Name: "n_detect", Data: &c.nDetect}, {Name: "n_actions", Data: &c.nActions}, {Name: "stage_mask", Data: &c.stageMask},
		{Name: "degraded", Data: &c.degraded}, {Name: "sink_context_count", Data: &c.sinkCtx}, {Name: "trace_id", Data: &c.trace},
	}
}

func b2u(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func (c *requestColumns) append(e *Event) {
	r := &e.Request
	c.tenant.Append(r.TenantID)
	c.session.Append(proto.UInt128{Low: be64(r.SessionID[8:]), High: be64(r.SessionID[:8])})
	c.ts.Append(r.TS)
	c.eventID.Append(r.EventID)
	c.agent.Append(r.AgentID)
	c.surface.Append(r.Surface.String())
	c.method.Append(r.Method)
	c.stream.Append(b2u(r.Stream))
	c.status.Append(r.Status)
	c.bytesIn.Append(r.BytesIn)
	c.bytesOut.Append(r.BytesOut)
	c.eventsOut.Append(r.EventsOut)
	c.tAuthn.Append(r.TAuthnUS)
	c.tScan.Append(r.TScanUS)
	c.tPolicy.Append(r.TPolicyUS)
	c.tRewrite.Append(r.TRewriteUS)
	c.tTotal.Append(r.TTotalAddedUS)
	c.hold.Append(r.HoldbackP99US)
	c.nDetect.Append(r.NDetect)
	c.nActions.Append(r.NActions)
	c.stageMask.Append(r.StageMask)
	c.degraded.Append(b2u(r.Degraded))
	c.sinkCtx.Append(r.SinkContextCount)
	c.trace.Append(r.TraceID[:])
}

func be64(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 | uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

// WriteBatch inserts the batch as ONE block with a deduplication token, so a
// retry after a timeout is idempotent on the server side (the table's
// deduplication window must be enabled; verify against the server version).
func (s *CHSink) WriteBatch(ctx context.Context, batch []*Event) error {
	cols := newRequestColumns()
	for _, e := range batch {
		if e.Kind != KindRequest {
			return fmt.Errorf("%w (kind %d)", ErrUnsupportedKind, e.Kind)
		}
		cols.append(e)
	}
	token := fmt.Sprintf("%s:request_events:%d", s.cfg.Node, s.seq.Add(1))
	var c *ch.Client
	select {
	case c = <-s.pool:
	case <-ctx.Done():
		return ctx.Err()
	}
	err := c.Do(ctx, ch.Query{
		Body:     "INSERT INTO tw.request_events VALUES",
		Input:    cols.input(),
		Settings: []ch.Setting{{Key: "insert_deduplication_token", Value: token}},
	})
	if err != nil { // the connection state is unknown: replace it
		_ = c.Close()
		if nc, derr := s.dial(ctx); derr == nil {
			s.pool <- nc
		} else {
			s.pool <- c // keep a slot; the next use will fail and redial
		}
		return err
	}
	s.pool <- c
	return nil
}

// ---- migrations -----------------------------------------------------------------

// Migrate applies the embedded or supplied migrations in order, recording each
// (with a checksum) in tw.schema_migrations. Re-running is a no-op; an applied
// migration whose file changed is an error (migrations are immutable).
func Migrate(ctx context.Context, c *ch.Client, migrations fs.FS, dir string) ([]string, error) {
	if err := c.Do(ctx, ch.Query{Body: "CREATE DATABASE IF NOT EXISTS tw"}); err != nil {
		return nil, err
	}
	if err := c.Do(ctx, ch.Query{Body: `CREATE TABLE IF NOT EXISTS tw.schema_migrations
		(version UInt32, name String, checksum String, applied_at DateTime DEFAULT now()) ENGINE = MergeTree ORDER BY version`}); err != nil {
		return nil, err
	}
	var ver proto.ColUInt32
	var sums proto.ColStr
	if err := c.Do(ctx, ch.Query{Body: "SELECT version, checksum FROM tw.schema_migrations ORDER BY version",
		Result: proto.Results{{Name: "version", Data: &ver}, {Name: "checksum", Data: &sums}}}); err != nil {
		return nil, err
	}
	applied := map[uint32]string{}
	for i := 0; i < ver.Rows(); i++ {
		applied[ver.Row(i)] = sums.Row(i)
	}
	files, err := fs.Glob(migrations, dir+"/*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var done []string
	for _, f := range files {
		var n uint32
		base := f[strings.LastIndex(f, "/")+1:]
		if _, err := fmt.Sscanf(base, "%d_", &n); err != nil {
			return done, fmt.Errorf("migration %q: name must start with a number and underscore", base)
		}
		body, err := fs.ReadFile(migrations, f)
		if err != nil {
			return done, err
		}
		sum := sha256.Sum256(body)
		sumHex := hex.EncodeToString(sum[:])
		if old, ok := applied[n]; ok {
			if old != sumHex {
				return done, fmt.Errorf("migration %s was modified after it was applied (checksum mismatch): migrations are immutable", base)
			}
			continue
		}
		for _, stmt := range splitStatements(string(body)) {
			if err := c.Do(ctx, ch.Query{Body: stmt}); err != nil {
				return done, fmt.Errorf("migration %s: %w", base, err)
			}
		}
		rec := fmt.Sprintf("INSERT INTO tw.schema_migrations (version, name, checksum) VALUES (%d, '%s', '%s')", n, strings.ReplaceAll(base, "'", ""), sumHex)
		if err := c.Do(ctx, ch.Query{Body: rec}); err != nil {
			return done, err
		}
		done = append(done, base)
	}
	return done, nil
}

// splitStatements splits SQL on statement-terminating semicolons, ignoring
// `--` comments. (The migrations contain no semicolons inside string literals.)
func splitStatements(sql string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		cur.WriteString(line)
		cur.WriteByte('\n')
		if strings.HasSuffix(strings.TrimSpace(line), ";") {
			if s := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(cur.String()), ";")); s != "" {
				out = append(out, s)
			}
			cur.Reset()
		}
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		out = append(out, s)
	}
	return out
}
