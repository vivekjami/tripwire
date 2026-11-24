-- Tripwire lineage schema v1 (PROVISIONAL until Phase 4). ARCHITECTURE §10.6.
-- Column ORDER is part of the contract: internal/lineage maps structs to these
-- columns positionally (TestDDLMatchesStructs guards drift).
CREATE DATABASE IF NOT EXISTS tw;

CREATE TABLE IF NOT EXISTS tw.tag_events
(
    tenant_id        LowCardinality(String),
    session_id       UInt128,
    ts               DateTime64(3, 'UTC')           CODEC(DoubleDelta, ZSTD(1)),
    event_id         UInt64                         CODEC(Delta, ZSTD(1)),
    tag_id           UInt128                        CODEC(ZSTD(1)),
    key_epoch        UInt16,
    data_class       LowCardinality(String),
    source_kind      Enum8('tool_result'=1,'resource'=2,'user_input'=3,'model_output'=4,'header'=5,'inferred_tool'=6),
    source_server    LowCardinality(String),
    source_tool      LowCardinality(String),
    source_call_hash UInt64,
    source_ref_hash  UInt64,
    agent_id         LowCardinality(String),
    confidence       UInt8,
    preview          FixedString(4) DEFAULT '',
    trace_id         FixedString(16),
    INDEX idx_tag tag_id TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (tenant_id, session_id, ts, event_id)
TTL toDateTime(ts) + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS tw.flow_events
(
    tenant_id     LowCardinality(String),
    session_id    UInt128,
    ts            DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    event_id      UInt64               CODEC(Delta, ZSTD(1)),
    tag_id        UInt128,
    edge_kind     Enum8('exact'=1,'shingle'=2),
    sink_kind     Enum8('model'=1,'tool'=2,'user'=3,'tool_header'=4),
    sink_name     LowCardinality(String),
    sink_tier     LowCardinality(String),
    direction     Enum8('to_model'=1,'from_model'=2,'to_tool'=3,'from_tool'=4,'to_user'=5,'to_tool_header'=6),
    agent_id      LowCardinality(String),
    data_class    LowCardinality(String),
    action        Enum8('allow'=1,'redact'=2,'tokenize'=3,'require_approval'=4,'block'=5),
    mode          Enum8('enforce'=1,'monitor'=2,'shadow'=3),
    rule_id       LowCardinality(String),
    policy_ver    UInt32,
    msg_index     UInt16,
    span_start    UInt32,
    span_len      UInt16,
    would_have    Enum8('none'=0,'allow'=1,'redact'=2,'tokenize'=3,'require_approval'=4,'block'=5) DEFAULT 'none',
    trace_id      FixedString(16),
    INDEX idx_tag tag_id TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (tenant_id, session_id, ts, event_id)
TTL toDateTime(ts) + INTERVAL 90 DAY DELETE;

CREATE TABLE IF NOT EXISTS tw.finding_events
(
    tenant_id        LowCardinality(String),
    session_id       UInt128,
    ts               DateTime64(3, 'UTC'),
    event_id         UInt64,
    finding_class    LowCardinality(String),
    detectors        Array(LowCardinality(String)),
    score            UInt8,
    source_kind      Enum8('tool_result'=1,'resource'=2,'tool_meta'=3,'user_input'=4,'model_output'=5),
    source_server    LowCardinality(String),
    source_tool      LowCardinality(String),
    source_call_hash UInt64,
    content_fp       UInt64,
    agent_id         LowCardinality(String),
    trace_id         FixedString(16)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (tenant_id, session_id, ts, event_id)
TTL toDateTime(ts) + INTERVAL 90 DAY DELETE;

CREATE TABLE IF NOT EXISTS tw.request_events
(
    tenant_id          LowCardinality(String),
    session_id         UInt128,
    ts                 DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    event_id           UInt64               CODEC(Delta, ZSTD(1)),
    agent_id           LowCardinality(String),
    surface            Enum8('chat'=1,'responses'=2,'mcp'=3),
    method             LowCardinality(String),
    stream             UInt8,
    status             UInt16,
    bytes_in           UInt32,
    bytes_out          UInt32,
    events_out         UInt32,
    t_authn_us         UInt32,
    t_scan_us          UInt32,
    t_policy_us        UInt32,
    t_rewrite_us       UInt32,
    t_total_added_us   UInt32,
    holdback_p99_us    UInt32,
    n_detect           UInt16,
    n_actions          UInt16,
    stage_mask         UInt8,
    degraded           UInt8,
    sink_context_count UInt32,
    trace_id           FixedString(16)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (tenant_id, ts)
TTL toDateTime(ts) + INTERVAL 14 DAY DELETE;
