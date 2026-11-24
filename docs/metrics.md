# Metric names (frozen at the end of Phase 1)

Dashboards, alerts and the benchmark tooling depend on these. Renaming or relabelling one is an ADR-gated change
(IMPLEMENTATION_PLAN §3). Every labelled family is created with all of its label values at startup, so a series
never appears for the first time during an incident. Label values are bounded; **no label carries a payload, an
agent-supplied string, or a detected value** (`upstream` is a configured name; `agent`/`tenant` are deliberately
not metric labels: per-agent numbers live in the lineage ledger).

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| tw_http_requests_total | counter | class (1xx..5xx) | data-plane requests by status class |
| tw_http_request_seconds | histogram (native + classic) | | total request duration |
| tw_inflight_requests | gauge | | requests being served |
| tw_shed_total | counter | reason (global_inflight, agent_rate, stream_cap, framing) | requests refused by admission control |
| tw_auth_failures_total | counter | | rejected authentications (the reason is deliberately not exposed) |
| tw_panics_total | counter | | recovered handler panics (failed closed) |
| tw_tls_reload_total | counter | result (ok, error) | TLS certificate reload attempts |
| tw_registry_reload_total | counter | result (ok, error) | agent-registry reload attempts |
| tw_registry_agents | gauge | | agents in the current snapshot |
| tw_upstream_requests_total | counter | upstream, class | upstream calls (class: 1xx..5xx or error) |
| tw_upstream_seconds | histogram (native + classic) | upstream | upstream call duration (non-stream: whole response) |
| tw_streams_active | gauge | | streaming responses in progress |
| tw_streams_total | counter | result | finished streams by outcome |
| tw_stream_events_total | counter | | SSE events relayed |
| tw_stream_bytes_total | counter | | SSE bytes relayed to clients |
| tw_stream_event_added_seconds | histogram (native + classic) | | time the gateway held an event: fully received -> flushed |
| tw_stream_first_event_seconds | histogram (native + classic) | | request start -> first event flushed |
| tw_lineage_events_total | counter | | lineage events accepted into the ring |
| tw_lineage_dropped_total | counter | | events dropped because the ring was full |
| tw_lineage_committed_total | counter | | events acknowledged by the sink |
| tw_lineage_failed_total | counter | | events lost after sink retries |
| tw_lineage_queue_depth | gauge | | events waiting in the ring |
| tw_lineage_batch_rows | histogram | | rows per sink batch |

Process and Go runtime metrics come from the standard Prometheus collectors and are not part of this contract.
