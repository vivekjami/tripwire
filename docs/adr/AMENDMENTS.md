# ADR amendments

Deviations from, or additions to, ARCHITECTURE.md, recorded **when they are made**
(IMPLEMENTATION_PLAN §2.3). Newest last. Format: what changed, why, evidence, revisit trigger.

## Phase 0

### AMD-001: mock control travels in the request body, not headers
`twmock` is steered by `metadata.tw_mock` (a JSON string in a standard OpenAI field) and `arguments.tw_mock` for MCP, instead of `X-TW-*` headers.
**Why:** the gateway will forward only an allow-list of outbound headers (T18); a header-based control channel would be silently stripped and the mock would fall back to defaults while the test appeared to pass. A body field survives any correct gateway and keeps requests schema-valid.
**Cost:** the gateway's "unknown/metadata strings" scan sees the control string; harmless (it is benign JSON) and in fact exercises the generic-string profile.
**Revisit when:** a gateway rule needs to strip `metadata` entirely.

### AMD-002: synthetic benign corpus for the mock until Phase 3
The plan asks for public-domain prose with source/licence recorded. Phase 0 generates text from an authored word list (`internal/mock/text.go`), deliberately free of digits, `@` and credential-shaped tokens so any detection on it is by construction a false positive (asserted by `TestBenignTextHasNoDigitsOrAt`).
**Why:** no network access to fetch and license-check a corpus in this session; the harness needs benign text now, not realistic text.
**Revisit when:** Phase 3 false-positives-per-1,000 measurement, which needs real prose (Project Gutenberg or similar), recorded in `eval/LICENSES.md`.

### AMD-003: toolchain pinned to Go 1.26.11, not 1.26.0
`go.mod` pins `go 1.26.11` (`toolchain go1.26.11`).
**Why:** `govulncheck` against Go 1.26.0 reported 29 reachable standard-library vulnerabilities (e.g. `crypto/x509`, fixed in 1.26.1+). Evidence: run on 2026-11-22; after the bump, "No vulnerabilities found".
**Revisit when:** each new 1.26 patch release (CI runs `govulncheck` on every PR).

### AMD-004: cleartext HTTP/2 via `http.Protocols`, not `x/net/http2/h2c`
`staticcheck` (SA1019) flags `x/net/http2.Transport`, `http2.Server` and `h2c` as deprecated in favour of `http.Transport/Server.Protocols` (Go 1.24+). All h2c code (twload client, twnull up/downstream, twmock) uses the standard library; `TestH2CClient` and `TestH2CDownstream` assert the server really negotiates HTTP/2.
**Revisit when:** a feature the stdlib lacks is needed (e.g. custom `SETTINGS` beyond `HTTP2Config`).

### AMD-005: the pass-through proxy buffers the (bounded) request body
`twnull` reads the request body (≤ 8 MiB) and sends it from memory instead of handing the inbound `r.Body` to the outbound transport.
**Why:** a real bug found by the harness's own error accounting: with the body coupled, ~0.5 % of long concurrent streams were truncated (`use of closed network connection` on the upstream read; the request context was *not* cancelled). Regression: `TestConcurrentPostStreamsAreNotTruncated`. It also matches the gateway design (ADR-05: the request is decided before it is forwarded), so the floor stays comparable.
**Revisit when:** a very-large-prompt workload makes request buffering the dominant cost (ADR-05's own trigger).

### AMD-006: the load dispatcher spins before each arrival, with a measured margin
Go timer wake-ups overshoot by ≈ 0.2-1.2 ms on this WSL2 host (`twload timer`; table in `docs/phases/P0.md`). `twload` therefore sleeps for the bulk of a gap and busy-waits the last `--spin-margin` (default 1.5 ms). The rig sets the margin from `twload timer` on bare VMs.
**Cost:** one core near 100 % at high rates; it is counted in the reported generator CPU (invalidation threshold 60 %).
**Revisit when:** rig measurements show tens-of-µs overshoot (then lower the margin and reclaim the core).

### AMD-007: a run is invalid if arrivals were never sent
In addition to the plan's two invalidation rules (generator CPU > 60 %, dispatch-lag p99 > 200 µs), a run is invalid if any scheduled arrival in the window was **never dispatched** (`undispatched > 0`). Without this a generator pinned at `--max-inflight` would quietly report a lower offered load as if it were the target. `TestInvalidRunIsFlagged` covers it.

### AMD-008: mock emission uses runtime timers, not a custom timer wheel
The plan prefers a timer wheel for mock emission to bound jitter. The mock uses `time.Sleep` to an *absolute* schedule (no cumulative drift) and records `actual − scheduled` per event (`mock_stats.emit_jitter`). Measured at ≈ 200 concurrent streams on WSL2: p99 ≈ 1.8 ms (`TestSelfCheckMockEmissionJitter`). Per-event *latency* measurement is unaffected because the true emit time is stamped, not the scheduled one; jitter only perturbs inter-event spacing.
**Revisit when:** rig jitter at 26 K streams exceeds ≈ 1 ms p99 or makes inter-event spacing unrealistic; then build the wheel.

### AMD-009: result files carry no hostname and scrub home paths
`env.json` omits the hostname; paths in `env.json`/`config.json` have the home directory replaced by `~` (`envinfo.ScrubHome`). Result directories are committed and may be public. Tested by `TestNoHostnameOrHomePathsInEnv`.

### AMD-010: rig tooling is provider-agnostic
`deploy/rig/rig.sh` supports bring-your-own hosts and a provider hook; **no Terraform/cloud scripts are shipped** because the provider is a user decision not yet made (see `docs/phases/P0.md` open items). Consequence: the plan's "`make rig-down` verified (no orphaned resources)" criterion cannot be met until a provider hook exists.

### AMD-011: stream sampling uses an avalanche-finalized hash
`groundtruth.Sampled` (shared by twmock and twload to decide which streams get emit-timestamp logging and checks) hashed ids with FNV-1a and took the high bits. For structured ids (`<run-id>-<n>`) that is poorly distributed: a requested 10 % sample came out between ≈ 5 % and 35 % depending on the run prefix, found when the joined-event counts of the first committed local runs did not scale with `-emit-sample`. Fixed with a murmur3 finalizer; `TestSampledUniformForStructuredIDs` fails on the old hash (12-13 % for a requested 10 %, 6.5 % for 5 %) and passes on the new.
**Consequence:** the first batch of `p0-local-*` results (never published) was regenerated; any result produced before commit "groundtruth: fix biased stream sampling" has a non-uniform sampled subset and must not be used for per-event percentiles.
