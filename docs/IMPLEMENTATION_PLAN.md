# Tripwire — Phase-by-Phase Implementation Plan

**Audience:** the engineer building it (you), as a working document, not a pitch.
**Companions:** [README.md](../README.md) (what/why) · [ARCHITECTURE.md](ARCHITECTURE.md) (design, tradeoffs, decision log; referenced here as `A§n` and `ADR-nn`).
**Rule of the plan:** every phase ends with **measurable exit criteria**. A phase is not done because the code exists; it is done because a number, a test, or a raw result file says so.

---

## Contents

1. [Scope, effort, and an honest calendar](#1-scope-effort-and-an-honest-calendar)
2. [Working agreements](#2-working-agreements)
3. [Contracts to freeze early](#3-contracts-to-freeze-early)
4. [Phase 0 — Foundations and the measurement harness](#4-phase-0--foundations-and-the-measurement-harness)
5. [Phase 1 — Core proxy and stream plumbing](#5-phase-1--core-proxy-and-stream-plumbing)
6. [Phase 2 — Streaming inspection and MCP](#6-phase-2--streaming-inspection-and-mcp)
7. [Phase 3 — Detection cascade, evaluation, policy completeness](#7-phase-3--detection-cascade-evaluation-policy-completeness)
8. [Phase 4 — Lineage](#8-phase-4--lineage)
9. [Phase 5 — Load, fuzz, failure injection, write-up](#9-phase-5--load-fuzz-failure-injection-write-up)
10. [Phase 6 — Buffer, hardening, stretch](#10-phase-6--buffer-hardening-stretch)
11. [Test strategy](#11-test-strategy)
12. [Benchmark protocol and pre-registration](#12-benchmark-protocol-and-pre-registration)
13. [Claims ledger](#13-claims-ledger)
14. [Risk register and the ordered cut list](#14-risk-register-and-the-ordered-cut-list)
15. [Dependencies (candidates, with selection criteria)](#15-dependencies-candidates-with-selection-criteria)
16. [The first ten working days, task by task](#16-the-first-ten-working-days-task-by-task)
17. [Definition of done for v0.1](#17-definition-of-done-for-v01)

---

## 1. Scope, effort, and an honest calendar

### 1.1 What "no compromise" means in this plan

**Everything the brief names is in scope and has an exit criterion:**

| Brief line | Phase where it is *built* | Phase where it is *proven* |
|---|---|---|
| Proxy (Go): OpenAI-compatible **and** MCP endpoints | 1, 2 | 2, 5 |
| Streaming (SSE) inspection without buffering whole responses | 1, 2 | 2, 5 |
| Per-agent identity and tool scoping | 1, 2 | 2 |
| Detection cascade (validators → dictionary/entity → ONNX only when unsure) | 2, 3 | 3, 5 |
| Lineage: tag at source, carry through prompts/tool calls, ClickHouse graph | 4 | 4, 5 |
| Policy: allow/redact/tokenize/require approval/block per class × agent × destination | 2, 3 | 3 |
| Injection defence + record which tool introduced it | 3, 4 | 3, 4 |
| < 10 ms p99 inspection, single-digit at p99 while streaming | all | 5 |
| Card number split across two stream chunks (sliding window) | 2 | 2, 5 |
| Precision vs recall; gateway not switched off | 3 (shadow/monitor, FP/1K) | 3, 5 |
| Proxy is an attack surface: every parser fuzzed | 1–4 (targets), 5 (campaign) | 5 |
| 20 K req/s streaming; adversarial P/R per class; `go test -fuzz`; 1 M lineage events/s | — | 5 |
| Four files: DESIGN, BENCHMARKS, FAILURES, write-up | — | 5 |

What *is* optional (and labelled **[stretch]** or on the cut list in §14): Responses API breadth, legacy-MCP resumption details, shingle lineage, `hold`-mode approvals, FPE, spotlighting, hash-chained audit, k8s packaging.

### 1.2 Effort estimate

The brief budgets **5 weeks at 30–40 h/week (≈ 150–200 h)**. The scope specified in ARCHITECTURE is larger than that budget assumes. My bottom-up estimate (±25 %):

| Phase | Hours | Notes |
|---|---:|---|
| 0 Foundations + harness | 28 | Harness is reusable across projects; this is the "shared test harness first" step from the brief, scoped to Tripwire's needs |
| 1 Core proxy + stream plumbing | 40 | Includes early ClickHouse ingest probe (risk R7) |
| 2 Streaming inspection + MCP | 56 | Highest-novelty code: hold-back, rewrite, MCP both revisions |
| 3 Cascade + eval + policy completeness | 60 | Largest phase; sidecar + models + eval set |
| 4 Lineage | 44 | Sessions, tagging, writer, queries, 1 M/s |
| 5 Load, fuzz, failure, write-up | 40 | Benchmarks, chaos, evidence files |
| 6 Buffer / hardening / stretch | 30 | Absorbs slippage |
| **Total** | **≈ 298 h** | |

| Option | Hours | Calendar at 35 h/week (40 h/week) | What you get |
|---|---:|---|---|
| **A. Full scope, buffer kept** | 298 | **≈ 8.5 weeks** (7.5) | Everything in this plan, with 30 h of slack |
| **B. Full brief scope, cut list C1–C7 applied (§14.2), buffer kept** | 272 | ≈ 7.8 weeks (6.8) | Everything the brief names; the seven non-brief items deferred |
| **C. B with the buffer removed** | 242 | ≈ 6.9 weeks (6.1) | Same scope as B with **zero slack**; only credible if Phase 0–2 actuals come in under estimate |
| **D. The brief's literal 5 weeks** | ≈ 175 | 5 weeks | **Not credible for this scope.** It would require dropping brief-named depth (e.g., no trained stage-3 models, a much smaller eval set, no ablations, a shortened fuzz campaign). Not recommended |
| **E. Half-time (15–20 h/week)** | as A/B/C | double the calendar | Same scope, linear |

**Stated plainly:** the brief's 5-week figure (≈ 150–200 h) understates what the brief's own "what you build / hard parts / proof plan" list costs when built to the standard in ARCHITECTURE. Cutting the seven non-brief items saves ≈ 26 h, which is real but small; the schedule is dominated by Phases 2–4. **Plan for A; decide between A, B and C at the end of Phase 2** (week ≈ 3.5), when the largest unknowns (hold-back correctness, MCP revision behaviour, the throughput floor) are resolved and the estimate can be recalibrated with actuals. The brief's printed calendar slot for this project is May 10 – Jun 13, 2027; nothing in the plan depends on it, so it can be pulled forward.

### 1.3 Relative calendar (week numbers from day 1)

```
Week  1   2   3   4   5   6   7   8   9
P0    ████
P1      ███████
P2          ████████████
P3                  ███████████
P4                          ████████
P5                                  ██████
P6                                        █████ (flex)
Brief's milestones (for mapping):
      [wk1-2: proxy + streaming inspection]=P1+P2   [wk3: cascade + eval]=P3
      [wk4: lineage]=P4                             [wk5: load, fuzz, write-up]=P5
```

### 1.4 Rig usage and cost control

- **Develop on a laptop** (Docker Compose: gateway, `twmock`, ClickHouse, Prometheus/Grafana/Tempo). Laptops are fine for correctness, fuzzing, profiling shape, and relative comparisons.
- **Rent the 3-VM rig by the hour only for benchmark sessions** (Phase 0 floor measurement; end of Phases 2, 3, 4; Phase 5 campaign). IaC in `deploy/rig/` creates and destroys it; a `make rig-down` guard is part of the exit checklist for every session. Budget expectation: tens of rig-hours total, not hundreds. Exact cost depends on the provider and instance type: record it in `bench/COSTS.md` as you go; do not estimate it in advance from memory.

---

## 2. Working agreements

1. **Trunk-based, small PRs** (≤ ~400 changed lines excluding generated/test data), each with tests; self-review checklist in the PR template (limits? deadlines? alloc? fuzz target? metric? doc?).
2. **Every phase starts with a 1-page "phase brief"** in `docs/phases/Pn.md`: objectives, WP list, exit criteria, risks. Every phase ends with a **retro entry**: estimate vs actual, surprises, ADR updates.
3. **ADRs are living.** Any deviation from ARCHITECTURE gets an ADR amendment *in the same PR*. The decision log is a deliverable (it feeds `DESIGN.md`).
4. **Performance gates in CI** from Phase 1: microbenchmarks with `benchstat` against a stored baseline (fail on > 10 % regression in gated benchmarks or any new allocation on 0-alloc paths); escape-analysis diff on hot packages.
5. **No number without a raw file.** README/BENCHMARKS numbers are generated by `scripts/report` from `bench/results/<run-id>/raw/`. Hand-typed numbers fail the docs check (see §13).
6. **Security defaults on from day one:** strict JSON, limits enforced, deadlines everywhere, `-race` in CI, `govulncheck` in CI, panics recovered at goroutine boundaries with explicit fail-closed behaviour.
7. **Fuzz targets are written *with* the parser**, not afterwards. A parser PR without its fuzz target is incomplete.
8. **Time-box research.** Library/model spikes ≤ 4 h each; the output is an ADR entry, not code.
9. **Weekly rhythm:** Monday plan from exit criteria; Wednesday mid-week estimate check (re-forecast the phase); Friday benchmark/eval snapshot into `bench/results/` or `eval/results/` and a 10-line status note.
10. **Commit hygiene for evidence:** result directories are immutable once published; reruns create new run IDs.

---

## 3. Contracts to freeze early

Freeze these at the **end of Phase 1** (interfaces) or **Phase 2** (event schemas) because everything else depends on them; changes after are ADR-gated.

| Contract | Defined in | Frozen by | Notes |
|---|---|---|---|
| `Scanner` interface and `State` (Save/Restore, ≤ 256 B) | `internal/detect` | end of P2 WP2.2 | Every detector implements it |
| `Detection{class, start, end, confidence, evidence, stage}` | `internal/detect` | P2 | Offsets are in **original byte coordinates** |
| `PolicySnapshot` + decision API: `Decide(span, ctx) Decision` | `internal/policy` | P2 WP2.6 | `Decision{action, params, rule_id, mode, would_have}` |
| Lineage event structs and ClickHouse DDL v1 | `internal/lineage`, `deploy/ch/` | P1 WP1.6 (provisional), P4 (final) | Column order stable; migrations versioned |
| Classifier sidecar protocol v1 | `internal/detect/clf` | P3 WP3.4 | Frame format, deadline semantics |
| Config schema v1 | `internal/config` | P2 | Strict unknown-field rejection; JSON Schema generated for editors |
| Session ID and tag ID derivation | `internal/lineage` | P4 | Changing it invalidates stored data |
| Metrics names/labels | `internal/obs` | P1 | Dashboards depend on them |

---

## 4. Phase 0 — Foundations and the measurement harness

**Duration:** ~4 working days · **Effort:** ≈ 28 h
**Why first:** the brief's rule is "build one reusable test harness in week one and run all projects through it." Every later claim depends on the harness being *correct*. A harness that suffers coordinated omission or measures its own bottleneck invalidates the whole project.

### Objectives

1. A repo that builds, tests, lints, fuzzes (smoke) and benchmarks in CI.
2. `twmock` and `twload` good enough to generate W1 and to *verify ground truth*.
3. A **null proxy** (pass-through) measured on the rig: the **floor** for added latency and CPU per event.
4. A fitted capacity model (`c_r`, `c_e`) and a go/no-go on rig sizing and transport choices.

### Work packages

**WP0.1 — Repo, toolchain, CI (4 h)**
- `go.mod` pinned to Go **1.26.x**; `toolchain` directive; Dockerfile (multi-stage, distroless final); Makefile (`make tools test lint fuzz-smoke bench-quick dev-up rig-up rig-down`).
- CI: `go vet`, `staticcheck`, `golangci-lint`, `govulncheck`, `go test -race ./...`, 30-s fuzz smoke per target, benchmarks uploaded as artifacts, escape-analysis diff for `internal/{sse,jsonscan,detect}`.
- Conventions doc: error wrapping, context/deadline rules, "no panic escapes a goroutine", logging allow-list, metric naming, package layout from README §9.

**WP0.2 — `twmock` (7 h)**
- **LLM mock** (OpenAI-compatible): `POST /v1/chat/completions` (JSON and SSE) and a Responses subset.
  - *Shape controls:* events-per-response distribution (fixed, geometric, empirical from trace), inter-event gap distribution (constant, lognormal, empirical), token text from a corpus (public-domain prose; source and licence recorded).
  - ***Ground-truth injection:*** `inject: {class, count, positions}`; values come from the **same generators the eval set uses** (valid-by-checksum, fake). The mock writes a **sidecar ground-truth log** `(stream_id, class, value_hash, byte_offset_in_decoded_text, event_boundaries)`. Chunking modes: `per-char`, `random(p)`, `at-every-boundary`, `adversarial` (split inside digit groups, inside `\uXXXX`, inside UTF-8 sequences).
  - *Fault modes:* reset mid-stream, stall N ms, malformed SSE, oversize event, duplicate JSON keys, invalid UTF-8 (all deterministic by seed).
  - *Emission timestamping:* each event carries a monotonic emit timestamp recorded to a per-stream log (not on the wire) for the latency join.
- **MCP mock** (both revisions): `tools/list`, `tools/call`, `resources/read`, `prompts/get`; revision negotiation; stateless and session behaviours; results with seeded values; **hostile mode** (tool descriptions that mutate; results carrying instructions; header/body mismatching *client* to test the gateway's rejection).

**WP0.3 — `twload` (8 h)**
- **Open-loop scheduler:** precompute intended send times (Poisson or trace-scaled bursts) → dispatch to a worker pool sized to avoid becoming the bottleneck → latency measured from **intended** send time (HdrHistogram, 1 µs resolution, 3 significant digits).
- **Streams:** record per-event receive timestamps and join with `twmock`'s emit log (same host, same monotonic clock) → per-event added latency after subtracting the null-proxy baseline.
- **Ground-truth checker:** reassemble client-visible text; assert **no clear bytes of any injected value** (for strict-tier classes); count FP (benign text altered) against a golden expected-output when no injection.
- **BurstGPT importer:** arrival process and token-length distributions from the public trace (**verify the trace's actual schema/licence at import time**); scale to target mean rate.
- **Modes:** `http`, `mcp`, `lineage` (synthetic events directly into the emitter or ClickHouse writer), `connections` (idle storm).
- **Output:** `results/<run-id>/{env.json, raw/*.hdr, raw/*.csv, summary.json}`; `env.json` captured automatically (kernel, CPU, governor, sysctls, NIC, git SHA, Go version, flags).
- **Self-validation tests (mandatory, they are the point of the phase):**
  1. *Coordinated-omission test:* inject a 500 ms stall into the mock at a known time; assert the recorded p99/p99.9 reflect it (a closed-loop generator would hide it).
  2. *Generator headroom test:* run against a trivially fast mock; assert generator CPU < 60 % and its own scheduling jitter p99 < 200 µs at 30 K req/s.
  3. *Clock join test:* measure a known fixed delay injected by a proxy; recovered value within ±50 µs.

**WP0.4 — Null proxy and the floor (5 h)**
- A pass-through streaming reverse proxy with the **exact edge configuration** the gateway will use (listeners, h2/h1, flush discipline, deadlines, upstream pool) but **no parsing**.
- Measure on laptop first (shape), then on the rig for: 5 K / 10 K / 20 K / 30 K req/s at W1; events/response ∈ {16, 64, 256}; h1 vs h2 upstream; with/without TLS downstream.
- **Record:** CPU/core-s per event and per request (fit `c_e`, `c_r`), p50/p99/p99.9 added latency of the *null* proxy, port/FD/TIME_WAIT behaviour, kernel settings that mattered, the **knee**.
- **Decisions to make from data (write ADR-amendments):** upstream transport for the benchmark (h1 with multi-port vs h2), whether downstream benchmark runs TLS-on or h2c, `GOMAXPROCS`/cpuset layout, whether the rig size is adequate for 20 K at W1 (R1).

**WP0.5 — Rig IaC and runbook (3 h)**
- `deploy/rig/` Terraform or provider CLI scripts: 3 VMs (A: loadgen+mocks, B: gateway+sidecar, C: ClickHouse+observability), sysctl profile, cpusets, NIC IRQ affinity, NTP, tooling install; `make rig-up/rig-down`; `bench/RUNBOOK.md` (pre-flight checklist: governor, THP, ulimits, clock sync, cold-start warm-up).

**WP0.6 — Observability baseline (3 h)**
- Prometheus metrics endpoint, OTel SDK wiring (no-op exporter by default), Grafana dashboards-as-code (RED, stage latencies, stream gauges), pprof on the admin listener, `request_events` struct (no ClickHouse yet).

**WP0.7 — Data-class registry and eval generator skeleton (2 h)**
- `eval/classes.yaml` (taxonomy from A§6.2 with validators and tiers), generator interface, first generators (PAN, AWS key, GitHub token, email) so `twmock` ground truth works from day one.

### Exit criteria (Phase 0)

- [ ] CI green on a clean checkout; `make bench-quick` runs end-to-end on a laptop.
- [ ] **Harness self-validation tests pass** (coordinated omission, headroom, clock join).
- [ ] Null-proxy floor recorded for W1 at ≥ 3 loads with ≥ 5 runs each, with CIs; `env.json` complete.
- [ ] Capacity model fitted; **R1 decision recorded:** (a) rig adequate for 20 K at W1, or (b) rig needs a larger gateway VM / different transport; the plan adjusts *now*.
- [ ] Upstream transport and TLS choices for published benchmarks recorded as ADR amendments.
- [ ] `make rig-down` verified (no orphaned resources).

### Risks and mitigations

| Risk | Mitigation |
|---|---|
| The load generator becomes the bottleneck | Headroom test; pin cores; if needed shard generator across two processes/cores sets |
| Mock emission jitter pollutes per-event latency | Pin mock to its own cores; timer-wheel emission instead of one timer per stream; verify emission jitter p99 in the self-validation suite |
| Port exhaustion invalidates results | Decided in WP0.4 (h2 upstream or multi-port); document |

---

## 5. Phase 1 — Core proxy and stream plumbing

**Duration:** ~1 week · **Effort:** ≈ 40 h · **Brief mapping:** "weeks 1–2 proxy and streaming inspection" (first half)
**Goal:** a **secure, observable, correct pass-through-with-parsing** gateway: it authenticates, routes, parses OpenAI traffic with the production JSON scanner and SSE codec, enforces limits, forwards, and emits request events — **with no detectors yet**. The parsing cost is therefore measured in isolation before inspection cost is added.

### Work packages

**WP1.1 — Edge and lifecycle (5 h)** — `A§3.3, A§12.4–12.5, A§14`
- Listeners (h1/h2, h2c, TLS with cert hot-reload), accept/connection/header/body/idle limits, graceful drain on SIGTERM (`drain_timeout`), admin listener (separate port, mTLS-ready) for `/metrics`, `/debug/pprof`, `/healthz`, `/readyz`.
- Strict YAML config loader (unknown-field rejection, defaults, validation errors with line numbers); JSON Schema generation.
- `GOMEMLIMIT`/`GOMAXPROCS` handling; startup banner includes toolchain, build info, bundle versions.

**WP1.2 — AuthN, registry, limits (6 h)** — `A§8`
- API keys (hashed, peppered, constant-time), JWT (EdDSA/ES256/RS256, alg allow-list, JWKS cache with `stale-if-error`, per-token verification cache), mTLS URI-SAN mapping.
- Agent registry as an `atomic.Pointer` snapshot; glob compiler for models/servers/tools; per-agent token bucket + concurrent-stream caps; global in-flight cap with 429 shedding.
- **Tests:** alg-confusion/`none`, expired/not-yet-valid, wrong audience, key rotation overlap, stale JWKS path, uniform failure timing (statistical test), registry reload under load.

**WP1.3 — Router and OpenAI non-stream path (6 h)** — `A§4.1`
- Route table; `POST /v1/chat/completions` (non-stream), `GET /v1/models` (filtered).
- Request body: bounded read, content-encoding handling with ratio cap, **strict JSON scan (v1: field location + duplicate-key/UTF-8 rejection)**, role-aware field walker interface (detector hook is a no-op).
- Upstream client: pooled h1/h2 transports, timeouts, **credential brokering** (strip inbound `Authorization`, inject upstream credential), header hygiene (hop-by-hop, `Accept-Encoding: identity`, propagate `traceparent`, add request id), retry policy (non-stream, idempotent only).
- Response: bounded read, JSON scan of `choices[].message`, Content-Length recompute path (used from P2 onward).
- **Tests:** header-leak test (inbound token never reaches upstream), smuggling suite (CL+TE, obs-fold), oversize/bomb, differential vs direct-to-mock on a corpus.

**WP1.4 — SSE codec and streaming passthrough (8 h)** — `A§5.2–5.3`
- Incremental decoder over a reused window; line-ending variants; BOM; comments; multi-line data; event/size limits; **verbatim-forward** of unmodified events; encoder for rewritten events.
- Streaming handler: headers flushed on first upstream byte; **single read-inspect-write loop**; `ResponseController` write deadlines; upstream cancellation on client disconnect; idle/total/byte caps; terminal events (`[DONE]`) handling; per-event timers wired to `tw_stream_event_added_seconds`.
- **Fuzz:** `FuzzSSEDecoder` with arbitrary TCP segmentation, differential against a reference parser (write a slow, obviously-correct one in `testkit`).
- **Tests:** slow client, abrupt disconnects both sides, upstream stall, goroutine/FD leak checks (`goleak`), flush-per-event timing test.

**WP1.5 — JSON scanner v2: streaming delta paths + splice API (8 h)** — `A§5.3, ADR-04`
- Locators for `choices[*].delta.{content,refusal,tool_calls[*].function.{name,arguments}}` and the response-body equivalents; **resumable JSON-string-escape decoder** (split `\uXXXX`, split surrogate pairs, split UTF-8); duplicate-key rejection; depth/size limits; position map for **splicing** replacements back into the original bytes.
- Strict `encoding/json` fallback path for non-hot shapes; routing logic between them.
- **Fuzz:** `FuzzJSONScan`, `FuzzJSONScanDiff` (gateway-view equals reference-view of the `content` string for every accepted input; any divergence is a finding), `FuzzDeltaRewriter` (splice then parse = expected).
- **Benchmarks (gated):** `BenchmarkJSONScanDelta` ≥ 500 MB/s, 0 allocs/op **[hypothesis, A§12.6]**.

**WP1.6 — Lineage skeleton and the early ClickHouse probe (5 h)** — `A§10.6–10.7, R7`
- `Emit(Event)` over a lock-free MPSC ring with pooled event structs; **null sink** now, ClickHouse writer stubbed.
- ClickHouse DDL v1 migrations (`deploy/ch/`) from A§10.6 and a migration runner; `ch-go` column-block writer prototype.
- **Early ingest probe (do not defer to Phase 4):** `twload --mode lineage` → writer → single ClickHouse node on rig C for 5 minutes at increasing rates; record the **ceiling**, part counts, merge pressure, CPU. Output: *a number and a list of ClickHouse settings that mattered*. This de-risks the 1 M/s requirement three weeks early.

**WP1.7 — Request events and stage timing (2 h)** — `A§11`
- Per-request `stagetimer` (monotonic, fixed array, no allocs), `request_events` emission, stage histograms, `Server-Timing` support gated to admin agents only.

### Exit criteria (Phase 1)

- [ ] **Compatibility:** official Python and TypeScript OpenAI SDKs (stream and non-stream), `curl`, and one third-party client work unchanged through the gateway against `twmock`.
- [ ] **Security tests:** header-leak, smuggling, oversize/bomb, alg-confusion, limit tests all pass.
- [ ] **Fuzz:** `FuzzSSEDecoder`, `FuzzJSONScan(Diff)`, `FuzzDeltaRewriter` each ≥ 10 min on CI/dev with no findings; seed corpora committed.
- [ ] **Performance (parse-only, no detectors):** at W1 on the rig, throughput reaches **≥ 90 % of the null-proxy knee**, with **p99 added latency ≤ 1 ms above the null proxy** at 70 % of knee **[hypothesis; if missed, profile and fix before Phase 2]**; **0 allocs/event** on the passthrough path; goroutine/FD counts flat after churn test.
- [ ] **Lineage probe result recorded:** sustainable insert rate and the settings that produced it; *if < 1 M rows/s, a plan is written* (batching, parts, second node, column trimming) before Phase 4.
- [ ] Frozen: metrics names, config schema v0.9, lineage DDL v1 (provisional).

### Risks

| Risk | Mitigation |
|---|---|
| `net/http` overhead dominates at 26 K streams | Profile early; consider tuning (header canonicalization, pooled writers) before reconsidering ADR-01 |
| h2 downstream per-event latency anomalies | Dedicated h2 stress test in this phase, not in Phase 5 |
| JSON scanner scope creep | Hard rule: scanner supports the hot shapes only; everything else uses the strict fallback |

---

## 6. Phase 2 — Streaming inspection and MCP

**Duration:** ~1.5 weeks · **Effort:** ≈ 56 h · **Brief mapping:** "weeks 1–2 … streaming inspection" (second half)
**Goal:** the **hold-back engine works and is provably chunk-invariant** for the highest-severity structural classes; the request path inspects and rewrites; MCP is gated, scoped and inspected on both spec revisions.

### Work packages

**WP2.1 — Normalizer, byte-class front-end, validators (7 h)** — `A§6.3, A§6.7`
- 256-entry byte-class tables; skip-ahead using accelerated search for anchors; **normalization folded into the walk** (zero-width skip-and-track, fullwidth/Arabic-Indic/Devanagari digit folding, original-offset tracking).
- Validators: Luhn + IIN range table, IBAN (country length table + mod-97), ABA (3-7-1), Verhoeff, SSN rules, PAN/other numeric shapes. Each with **table-driven tests from published test vectors** and `FuzzValidators` vs a reference implementation.
- **Benchmarks (gated):** prose ≥ 300 MB/s/core; digit-dense adversarial ≥ 10 MB/s/core **[hypothesis]**. If missed by > 2×, **stop and optimize the front-end** before adding detectors.

**WP2.2 — `StreamScanner` v1 and hold-back (14 h)** — `A§5.4, ADR-03`
- Implement the `Scanner` interface for **T1**: digit-run tracker (PAN, IBAN, ABA, Aadhaar, SSN), prefix-literal AC (AWS, GitHub, Slack, Stripe, Google, OpenAI/Anthropic-shaped, JWT), PEM `in_block` state, context keyword ring (64 B).
- **Hold-back protocol** exactly as A§5.4: `emit_upto = min(start of live strict candidates)`, candidate failure ⇒ release unchanged, candidate success ⇒ action output, overlap resolution, `flush()`, **max-hold timer** (250 ms default) with a testable fake clock.
- **Test suite (this is where correctness is won):**
  - *Golden strings* (≥ 60): spans at start/middle/end, adjacent spans, overlapping candidates, near-misses (Luhn-fail), prefix lookalikes, multi-byte UTF-8 neighbours, separators of every kind.
  - ***Exhaustive split harness:*** for each golden string, **every 2-way split** at every byte offset (including inside multi-byte and inside `\uXXXX`); **every 3-way split on a grid**; **10⁵ random k-way splits (k ≤ 20)** per CI run with a logged seed. Assertion: *output text and detection set are identical for all partitions.*
  - *Property tests* (`rapid`): chunk-invariance, idempotence, monotonicity (A§5.7).
  - *Differential:* vs a slow whole-text reference scanner on random + adversarial text.
  - `FuzzStreamScanner` (arbitrary partitions of arbitrary bytes), 30 min.
- **Benchmarks (gated):** scanner steady-state 0 allocs/op; `Save/Restore` cost; hold-back bytes distribution on prose = 0.

**WP2.3 — Delta rewriter, event modes, terminal handling, mid-stream block (7 h)** — `A§5.6, ADR-26`
- Splice rewriter with JSON-safe replacement encoding (no control characters, no newlines, escapes valid); modes `empty-delta` (default), `elide`, `coalesce`.
- Terminal events (`finish_reason`, `[DONE]`, `response.completed`) trigger `flush()` first; **mid-stream `block`** protocol (`content_filter` + error event + `[DONE]`/failure, upstream cancel, held-byte discard).
- **Compatibility matrix tests:** official Python/TS SDKs + raw SSE consumer + one third-party client for each mode; assert SDK-visible message equals expected redacted text.

**WP2.4 — Request-path inspection, message walker, cache v1 (7 h)** — `A§4.1, A§6.8, ADR-16`
- Role-aware walker over `messages[]` (string and part arrays; text parts only), `tools[]`, `response_format`, `metadata`, and **generic-string profile for unknown fields**.
- Message cache v1: sharded LRU (swap to W-TinyLFU later), key `(tenant, bundle_ver, norm_profile, xxh3(decoded text), role-kind)`, stores detections + `stage_mask`; **response priming** (hash the final assistant text *as the client will resend it*, post-rewrite).
- Splice-based request rewrite; `block` ⇒ HTTP 4xx with a documented JSON error body (class, rule id, request id; **never echoes the sensitive value**).
- **Tests:** history-growth test (cost per turn flat ≈ new bytes), cache-hit correctness (cached vs uncached decisions identical on a corpus), two-tenant isolation.

**WP2.5 — Tool-call argument streams and LLM-path scoping (4 h)** — `A§5.5`
- Double-decode (outer JSON string escapes → inner text view), key-aware confidence hook, name accumulation across events, early scope termination.
- **Tests:** arguments split mid-escape, mid-key, mid-value; name split across events; hallucinated tool names.

**WP2.6 — Policy engine v0 (6 h)** — `A§7.1–7.4, ADR-08`
- YAML schema, compiler/linter (shadowed/unreachable/contradictory rules), decision-table builder, `Decide()`, actions `allow|redact|block` (+ `monitor`/`shadow` modes and `would_have`), snapshot/hot-reload with signature-verify stub, golden decision tests (table-driven: `(class, direction, agent, dest) → action`).
- **Benchmark (gated):** `BenchmarkPolicyLookup` ≤ 100 ns typical **[hypothesis]**.

**WP2.7 — MCP adapter, both revisions (12 h)** — `A§4.4, ADR-12, ADR-13`
- JSON-RPC codec (id types, errors, notifications; batching only for legacy); revision detection by header/`initialize`.
- **`2026-07-28`:** per-request statelessness, **`Mcp-Method`/`Mcp-Name` ≡ body verification** (reject + audit on mismatch; fuzz casing/whitespace/Unicode/duplicate headers), `_meta` trace-context propagation, mirrored-header (`x-mcp-header`) inspection, POST-only endpoint, JSON and SSE responses, stream termination on final response, **no resumption**.
- **`2025-11-25`:** `initialize`, `Mcp-Session-Id` table (TTL, caps), GET stream if used by the server, `Last-Event-ID` passthrough with **hold-state discard on reconnect** (F-24).
- Scope: tool/resource/prompt allow-lists per agent, **`tools/list` filtering**, pin store (hash of `(name, description, schema, annotations)`), `tools/call` argument inspection (deep string walk), result inspection (JSON and SSE) with the *same* stream scanner, `Origin` validation, upstream credential brokering/OAuth client (client-credentials) with token cache, no passthrough.
- **Tests:** conformance suites per revision against `twmock` MCP and (where available) a reference MCP server SDK; scope matrix (allowed, hidden, lookalike names, whitespace, case); rug-pull mutation test; both-revision interoperability; fuzz targets (`FuzzMCPJSONRPC`, `FuzzMCPHeaderBody`).
- **Pre-work (30 min, day 1 of the phase):** re-read the current spec revisions and changelogs; record the exact revision strings and header requirements in `docs/mcp-notes.md`. Specs move; the notes make drift visible.

**WP2.8 — Responses API subset (4 h)** — `A§4.3` — *[cut-list C1 candidate]*
- Per-event-type schema table; `output_text.delta`, `refusal.delta`, `function_call_arguments.delta`, `mcp_call_arguments.delta`; final-object re-inspection on `response.completed`; **hosted-MCP bypass detection** (`tools[].type == "mcp"`) with block/rewrite policy; preserve `sequence_number` and `obfuscation`.

**WP2.9 — Ground-truth harness integration (3 h)** — *(shared with Phase 3)*
- `tweval stream` runs `twload` + `twmock` ground-truth injection at scale and reports **leak count** (clear bytes of strict-tier values at the client) and **benign alteration count**; wired into nightly CI at modest scale.

### Exit criteria (Phase 2)

- [ ] **Chunk-invariance:** exhaustive 2-way and grid 3-way split suites pass for all golden strings; 10⁵ random splits clean; `FuzzStreamScanner` 30 min clean.
- [ ] **Zero-leak e2e:** 100 K streams with seeded PAN/secret values at random split offsets across `per-char`, `random`, `adversarial` chunking ⇒ **0 leaked clear bytes** at the client; benign-text alteration = 0.
- [ ] **Latency (rig, W1-lite = 5 K req/s):** request-path p99 added ≤ 3 ms and stream per-event p99 added ≤ 2 ms *excluding hold-back*; **hold-back p99 on prose = 0**, on candidate bytes ≤ one upstream inter-event gap **[hypothesis; record actuals]**. If the stream path exceeds budget, profile before moving on.
- [ ] **MCP:** both revisions pass conformance; scope matrix green; header/body mismatch rejected in every fuzzed variant; `tools/list` filtering verified; pin-change detection verified.
- [ ] **SDK compatibility matrix** green for `empty-delta` (default) and documented for other modes.
- [ ] **Policy v0** golden decision tests green; monitor/shadow produce `would_have` correctly.
- [ ] **Recalibration checkpoint:** actual vs estimated hours recorded; decide **Option A, B or C** (§1.2) and finalize the cut list.

### Risks

| Risk | Mitigation |
|---|---|
| Hold-back bugs only appear under rare splits | Exhaustive + random split harness *is* the control; do not merge scanner changes without the full split run |
| SDK compatibility surprises with empty deltas | Test matrix early (WP2.3); `coalesce` as fallback; document |
| MCP spec details differ from notes | Day-1 spec re-read; conformance tests derived from spec text; keep adapter interface-isolated |
| T1 scanner performance below budget | WP2.1 gate stops the phase until fixed |

---
## 7. Phase 3 — Detection cascade, evaluation, policy completeness

**Duration:** ~1.7 weeks · **Effort:** ≈ 60 h · **Brief mapping:** "week 3 detection cascade and evaluation set"
**Goal:** the full three-stage cascade with a **budget governor**, the frozen adversarial **evaluation set** with per-class precision/recall, and the policy surface completed (`tokenize`, `require_approval`, fail-open/closed matrix) plus injection defence L0–L3.
**This is the largest phase.** If it slips, spill is absorbed by Phase 6 in the order given in §14.2 (C6 first).

### Work packages

**WP3.1 — Stage 2: AC engine, dictionaries, session-literal automaton (8 h)** — `A§6.4, ADR-24`
- Resumable Aho–Corasick: dense-table form (≤ 10 K states) and double-array form (large dictionaries), serializable state; case-folding and word-boundary options; per-tenant build off the hot path with atomic publish; memory caps.
- Session-literal automaton (small-set trie ≤ 32 literals, AC above), copy-on-write on tag-set change; **T2 hold-back** integration into `StreamScanner` (hold only while AC state ≠ root *within the session automaton*).
- Gazetteer + context heuristics for names/addresses (licence-checked sources recorded in `eval/LICENSES.md`).
- **Tests:** dictionary update during streams (in-flight streams unaffected); T2 split-invariance on the exhaustive harness (extends WP2.2); 1 M-term dictionary memory/latency profile; Bloom-prefilter ablation.

**WP3.2 — Stage 1 completion and T3 behaviours (8 h)** — `A§6.2–6.3, A§5.4`
- Emails (`@` anchor expansion), phones (digit-run + country rules), URL-embedded credentials, JWT structure + header decode, keyword/context windows (`cvv`, `password=`…), entropy detector with charset tests, `LABEL.*` phrase table, vendor-format **data file** loader (formats updatable without code).
- T3: anchor-triggered redaction of the remainder, **stream-leak event** for the already-emitted prefix, optional `strict_tail_hold`.
- Bounded base64/percent-decoding of candidate tokens (depth ≤ 2, ≤ 4 KiB), with offset mapping that redacts the *whole encoded token*.
- **Tests/fuzz:** `FuzzNormalizer` (offset maps monotone/reversible), obfuscation slices as unit tests, hard-negative regression corpus (every FP found becomes a test).

**WP3.3 — Confidence, calibration, uncertain band, budget governor (4 h)** — `A§6.6, ADR-06`
- Evidence combination (noisy-OR with ceilings), isotonic calibration pipeline (Python offline → threshold file consumed by Go), per-class `τ_lo/τ_hi/on_uncertain`.
- Governor: request deadline propagation via `context`, per-stage EWMAs (per-P, lock-free), admission rule, circuit breaker for the sidecar, `degraded` flags and metrics.
- **Tests:** synthetic slow-stage injection ⇒ governor skips stage 3 and p99 stays inside SLO; admission is monotone in remaining budget; degraded behaviour per `on_uncertain`.

**WP3.4 — `twclf` sidecar and models (14 h)** — `A§6.5, ADR-07`
- **Protocol v1** (length-prefixed binary over UDS, deadlines, request IDs, status codes), server loop with **dynamic micro-batching** (window taken from the request's remaining budget), ORT session pool with pinned intra-op threads, tokenizer in the sidecar, graceful restart; client in the gateway with deadline + circuit breaker.
- **Models (time-boxed, each ≤ 4 h of training/export effort; offline Python in `models/`):**
  1. `S3-SECRET`: small char-/token-level classifier on (token, context window): secret vs benign high-entropy.
  2. `S3-NER`: small token-classification model for PERSON/ADDRESS/ORG on ≤ 64-token windows (distilled/quantized small transformer **or** char-CNN-class model, chosen by the latency gate below).
  3. `S3-INJECT`: small classifier on ≤ 256-token chunks. **Candidates are evaluated, not assumed;** check each candidate's licence and size.
  - Export ONNX → int8 dynamic quantization → model card (data, metrics, licence, blind spots, artifact hash).
- **Latency gate:** stage-3 call p99 ≤ 3 ms for ≤ 8 spans × 64 tokens on the rig's sidecar cpuset (**[hypothesis]**). Decision rule on miss: smaller model for NER (recall trade documented), injection moved to async-only.
- **Tests:** frame fuzz (`FuzzSidecarProtocol`), kill -9 / SIGSTOP / slow-sidecar chaos (F-12, F-13), deadline accuracy (response never later than deadline + 200 µs), batching correctness (results independent of batch composition).

**WP3.5 — Evaluation set v1, runner, CI gate (10 h)** — `A§6.9, ADR-25`
- Template library (≥ 300 context templates across chat/tool-result/JSON/CSV/HTML/log/code/email/SQL), generators for every class, obfuscation transforms, hard-negative families, injection set (direct, paraphrase, multilingual, hidden-Unicode, markdown exfil, multi-step) **plus benign "discusses injection" negatives**.
- **Split by template family and seed**; test split frozen with a recorded hash; manifest lists generator versions.
- `tweval`: span-level strict/overlap P/R/F1, decision-level accuracy, **FP per 1,000 benign requests and per MB**, stream-leak rate, stage attribution, bootstrap CIs; report as Markdown + JSON.
- **CI gate:** dev-split regression tolerance per class; FP/1K ceiling per class; test split runs **only** in a manually triggered job whose invocations are logged (so "tuned on test" is detectable).
- Initial thresholds τ tuned on dev only.

**WP3.6 — Policy completion: tokenize, vault, approvals, failure matrix (10 h)** — `A§7.4–7.6, ADR-14, ADR-15, ADR-23`
- `tokenize`: token format and generator (HMAC per session key), **sharded in-process vault** with AES-256-GCM per-tenant DEK (AAD binds tenant/session/class), TTL and zeroization; **detokenization at MCP egress** (scan `arguments` for token prefix, verify session + clearance); re-tokenization of tool results; unknown-token handling and metric; test that tokens never re-trigger detectors.
- `require_approval` (`retry_with_grant`): structured error, approvals API (approver authN/RBAC, webhook notify), grants bound to `(agent, tool, sha256(canonical args), policy_version)`, one-time, TTL; CLI approve for dev. *`hold` mode is [stretch].*
- Failure matrix implemented and tested (A§7.4): detector panic, sidecar loss, policy eval error, vault down (⇒ `redact` fallback), approval service down (⇒ deny), JWKS down.
- Policy hot-reload with signed bundles (Ed25519), golden tests run at load time, last-good retention.
- Session predicates (`has_injection_flag`, `has_tag_class`, `distinct_destinations`) defined against a **session-state interface** (stub now; real implementation in Phase 4).

**WP3.7 — Injection defence L0–L3 (6 h)** — `A§9`
- L0 hidden-text detectors (Unicode tag chars, bidi, zero-width density, HTML-invisible hints); L1 signature table with proximity rules (EN + a small multilingual set) loaded from data; L2 `S3-INJECT` integration (nomination heuristics, async-eligible); L3 exfil-URL detection (markdown image/link, query/path carrying fingerprints or high-entropy blobs, host not in destination allow-list).
- Provenance: `finding_event` with `{source kind, server, tool, call_id_hash, resource_ref_hash, detectors, score, content_fp}`; session `injection_flag` set via the session interface; tool-description pin diff reported as a finding.
- **Tests:** injection set P/R per layer and combined; benign-negative FP rate; "tutorial discussing injection" false-positive audit; **trifecta scenario test** (end-to-end with the stub session) — full lineage-backed version lands in Phase 4.

### Exit criteria (Phase 3)

- [ ] **Per-class P/R/F1 table** (dev) for every class in the taxonomy × channel × obfuscation slice; **FP/1K benign requests below each class's target**; classes that miss target are in `monitor` with a written reason.
- [ ] **Frozen test split run once** at the end; results recorded with CIs; any tuning after that requires a *new* test split (generator seed bump) and is logged.
- [ ] **Request-path cascade latency** (rig, 5 K req/s, ≤ 16 KiB new content, stage 3 enabled on the uncertain band): p99 added ≤ 6 ms; **governor test:** with sidecar throttled, p99 stays ≤ 10 ms and `degraded` rate matches expectation.
- [ ] **Stage-3 latency gate** met or the fallback decision recorded.
- [ ] **Streaming:** T1/T2 zero-leak e2e re-run with the full cascade; **T3 stream-leak rate measured and published** per class; `strict_tail_hold` cost measured.
- [ ] **Tokenization:** round-trip test (model sees token; authorized tool receives real value; unauthorized tool receives token); no cross-tenant/session token reuse; vault-down ⇒ `redact`.
- [ ] **Approvals:** TOCTOU test (altered args after approval rejected), one-time use, expiry.
- [ ] **Injection:** per-layer metrics published; policy rule "trifecta" fires in scenario tests.
- [ ] All new fuzz targets ≥ 30 min clean.

### Risks

| Risk | Mitigation / contingency |
|---|---|
| Model work balloons | Hard 4-h box per model; ship heuristics-only for the class and mark stage-3 `experimental` |
| Eval set too easy ⇒ inflated scores | Hard-negative parity; third-party-text backgrounds; report per-slice, not only aggregate; keep a *blind* mini-set authored late |
| FP rate too high on real prose | Class demoted to `monitor`; context-only detectors; raise τ_hi; publish the trade |
| Calibration pipeline eats time | Start with per-class threshold sweeps; add isotonic only if reliability diagrams demand it |

---

## 8. Phase 4 — Lineage

**Duration:** ~1.2 weeks · **Effort:** ≈ 44 h · **Brief mapping:** "week 4 lineage store"
**Goal:** tags born at sources, linked at sinks, persisted in ClickHouse with a **1 M events/s** ingest pipeline that **never blocks the data path**, plus the investigation tooling that justifies all of it.

### Work packages

**WP4.1 — Session manager (6 h)** — `A§10.5, ADR-20`
- ID resolution (header → MCP session → history hash chain → idle window), `parent_session` on branching; sharded state with per-shard locks; per-session caps; LRU with global byte budget; TTL sweeper.
- **Tests:** truncated/summarized histories, branching conversations, concurrent requests in one session, state loss and rebuild (restart simulation), memory ceiling under 1 M synthetic sessions.

**WP4.2 — Tagger, fingerprints, keys (7 h)** — `A§10.2, ADR-21`
- Per-class normalization; HMAC-SHA256 fingerprints with per-tenant keys derived by HKDF from a master secret; `linkability: tenant|session`; `key_epoch`; source-direction detection ⇒ `tag_event`; **source labels** (`sources:` config) for record-level tagging; label-in-content promotion.
- **Tests:** same value ⇒ same tag across sessions (tenant mode) and different tags (session mode); cross-tenant tags differ; **privacy test:** inject known canary values, scan every ClickHouse table for raw values or trivially-derived encodings ⇒ zero hits; key-epoch rotation and cryptographic-erasure test.

**WP4.3 — Sink matching and linking (7 h)** — `A§10.3`
- EXACT: detection fingerprints looked up in the session tag index; session-literal matches (T2) as link evidence; `tool_call_id` correlation (assistant `tool_calls` ↔ `tool` messages ↔ MCP calls); `source_kind = inferred_tool` fallback.
- **[C2 / stretch]** SHINGLE: winnowed 5-gram fingerprints for record-level sources (cap 512/tag), rolling-hash sink matching enabled only for sessions that contain record-level tags.
- **Tests:** scenario suite (§11): tool result → next prompt → tool-call args → external destination, expecting a specific set of tag/flow rows; **negatives**: paraphrase/transform *not* linked (and reported as a known gap), look-alike value with different checksum not linked.

**WP4.4 — Emitter, WAL, ClickHouse writer (10 h)** — `A§10.7, ADR-11`
- Ring + per-class priorities; **audit-critical path** (enforced `block`/`require_approval` and approval decisions) with **synchronous group-commit WAL** (fsync ≤ 2 ms), everything else best-effort; WAL spill segments (CRC32C, rotation, recovery) when the ring passes high-water or ClickHouse errors; replayer.
- `ch-go` column-block writers (W goroutines), batch by rows/interval, LZ4 or none, **`insert_deduplication_token`**, retry with backoff and jitter, drop-with-counters on sustained failure; cardinality guard on `LowCardinality` columns; schema migrations applied by `twctl`.
- **Tests:** ClickHouse down/slow/"too many parts" chaos (F-14, F-15), WAL corruption/truncation recovery (`FuzzWALRecovery`), exactly-once-ish check: after chaos, `committed ≥ emitted − dropped` and duplicates identifiable by `event_id`; audit-critical durability test (kill -9 immediately after a block: the block is in the WAL).

**WP4.5 — Investigation tooling (6 h)** — `A§10.6`
- `twctl lineage forward|backward|session|exfil|injection|forget`, bounded-depth BFS, tabular + JSON output, `--explain` showing edge kinds (EXACT vs context-implied) explicitly; Grafana dashboards: sensitive-flow overview, shadow-report, injection provenance, lineage-pipeline health; saved parametrized ClickHouse queries.
- **Query performance protocol:** load 1 B synthetic rows (or the largest that fits the rig), record forward/backward/timeline p50/p95; **decide on the tag-centric projection** (A§10.6 note) from data.

**WP4.6 — The 1 M events/s benchmark (5 h)** — `A§10.7`
- Synthetic mix proportional to the measured real mix (tag:flow:finding:request); `twload --mode lineage` into `Emit()` at 1 M/s for **10 minutes**, also stepped 250 K → 500 K → 1 M → 1.5 M to find the ceiling.
- **Success criteria:** committed rows = emitted − dropped with **dropped = 0** at 1 M/s; writer enqueue p99; ring occupancy < 50 %; CPU of pipeline; ClickHouse parts count, merge backlog, insert latency; disk and network rates. Tune: batch rows, writer count, `max_insert_threads`, merge pool, compression.
- Then **end-to-end at W1** (≈ 100–160 K events/s) with the real gateway.

**WP4.7 — Session predicates and the trifecta, end to end (3 h)** — `A§9.5`
- Replace the Phase-3 session stub with the real session state; wire `has_injection_flag`, `has_tag_class`, `distinct_destinations`.
- **Scenario tests (the demo):** (1) agent reads a customer record via MCP (`resources/read`/`tools/call`), (2) a retrieved web page contains an injection, (3) the model tries `send_email` to an external address with the record's values ⇒ flows recorded, trifecta rule fires, approval required, and the **investigation query answers "which tool introduced the injection and what left"**.

### Exit criteria (Phase 4)

- [ ] **1 M events/s sustained 10 min with 0 dropped and 0 lost** (committed == emitted), with the ClickHouse settings and CPU/IO numbers archived; ceiling documented.
- [ ] **Data path unaffected:** with ClickHouse killed under W1 load, request/stream p99 unchanged within CI; lineage spills to WAL and replays on recovery.
- [ ] **Audit-critical durability** test passes (block recorded even on immediate crash).
- [ ] **Scenario suite** (≥ 12 scenarios incl. tenancy, restart/state-loss, branching sessions, tool-call-id correlation, negatives) passes with *exact expected row sets*.
- [ ] **Privacy:** zero raw values in any table; erasure by key-epoch retirement verified.
- [ ] **Investigation tooling** answers forward/backward/exfil/injection questions on the demo scenario in < 1 s on the dev data set and with documented latency on the large set; projection decision recorded.
- [ ] End-to-end W1 with lineage on: request/stream p99 within Phase 2/3 budgets.

### Risks

| Risk | Mitigation |
|---|---|
| ClickHouse parts/merge pressure at 1 M/s | Early probe (WP1.6) already measured; larger batches, fewer writers, tuned merge pool, second node as fallback (documented, not required) |
| Producer CPU for column building steals gateway cores | Benchmark `CHBlockBuild`; cpuset the writer goroutines? (Go cannot pin goroutines; reduce work via fixed-width columns, fewer LowCardinality conversions) |
| Session hash-chain mismatches in real SDK traffic | Test with real SDKs' serialization; fallback chain (idle window) and `parent_session` linking |

---

## 9. Phase 5 — Load, fuzz, failure injection, write-up

**Duration:** ~1 week · **Effort:** ≈ 40 h · **Brief mapping:** "week 5 load, fuzzing and write-up"
**Goal:** convert a working system into **evidence**: pre-registered benchmarks, a fuzz campaign, the failure report, the frozen eval result, and the four deliverable files.

### Work packages

**WP5.1 — Pre-register and run the benchmark matrix (10 h)** — see §12
- Commit `bench/PLAN.md` **before any final run**: workloads, metrics, success criteria, ablations, run counts, analysis method.
- Matrix: W1 at 5/10/15/20/25/30 K req/s (knee), events/response ∈ {16, 64, 256}, history-length sweep (1–64 turns), MCP `tools/call` mix, stage-3 fraction sweep (0–40 % of requests nominating spans), TLS on/off, h1/h2 upstream; **ablations:** message cache off, hold-back off (to show its cost), stage 3 off, lineage off, Green Tea GC vs `nogreenteagc`, `coalesce_window` 0 vs 1 ms.
- ≥ 5 runs per point, warm-up discarded, **HdrHistograms merged across runs** (never average percentiles), 95 % CIs on run-level statistics.

**WP5.2 — Capacity, USL fit, profiling, three time-boxed fixes (8 h)** — `A§12.1, A§12.7`
- Fit `R vs CPU` and the USL; locate the knee; **size at 70–80 % of knee** and show W1 at that operating point.
- CPU + off-CPU + alloc + mutex + scheduler-trace profiles at the knee; archive flame graphs; fix the **top three** hotspots (each ≤ 2 h), re-measure, record before/after.
- Tail forensics: use flight-recorder snapshots to explain **every** p99.9 outlier class found (GC, scheduler, h2 write contention, noisy neighbour).

**WP5.3 — Failure-injection suite → `FAILURES.md` (8 h)** — `A§13`
- Automate F-01…F-34 (toxiproxy, `tc netem`, `dm-delay`/`dm-flakey`, `kill -9`, `SIGSTOP`, clock steps, fill disk, malformed upstreams). Each test emits `{id, injected, expected, observed, verdict, fix_ref}` JSON; a script renders `FAILURES.md`.
- **Include negative results:** failures that were found, what was changed, and what remains (e.g., T3 leakage, paraphrase gap, dedupe window caveats).

**WP5.4 — Fuzz campaign (4 h wall + triage)** — `A§14.3`
- Every target ≥ 30 min on the rig; scanner/JSON/SSE/MCP-header targets ≥ 8 h overnight; corpus minimization; coverage report (`go tool covdata`/`-coverprofile` from fuzz corpora) for parser packages; **every crasher ⇒ fix + regression test**; log of crashers found and fixed is part of `FAILURES.md`.

**WP5.5 — Final evaluation run (3 h)**
- Run the frozen test split once (code frozen at a tagged commit); publish per-class tables with CIs, obfuscation slices, stream-leak rates, injection layer metrics, stage attribution; list **what the system misses** explicitly.

**WP5.6 — Documentation and write-up (6 h)**
- `DESIGN.md` distilled from ARCHITECTURE (goals, non-goals, failure model, **alternatives rejected and why**); `BENCHMARKS.md` (method, hardware, commit, workload definitions, charts regenerated by **one script** from raw data); `FAILURES.md`; README numbers filled from the claims ledger (§13).
- **The write-up:** one long post on a single hard decision end to end. Recommended: *"Redacting a card number that arrives one digit per SSE event: hold-back tiers, state machines, and the cost of being strict."* Include the split-invariance proof strategy, the measured hold-back cost, and the alternatives rejected.
- Repo polish: architecture diagram at top of README, headline numbers, one-command reproduction (`make repro`), pinned repo, topics.

**WP5.7 — Reproducibility drill (1 h + rig time)**
- From a **fresh VM trio** and a clean clone: `make rig-up && make bench-final` reproduces headline numbers within the published CIs. Any discrepancy ⇒ investigate before publishing.

### Exit criteria (Phase 5) — the brief's proof plan, line by line

- [ ] **20 K req/s with streaming responses** at W1, with the p99 latency the proxy adds (request path, per event, hold-back reported separately), CIs, knee, and sizing — **or the measured knee and its profile, stated as the claim** if 20 K is not reached.
- [ ] **Adversarial evaluation:** P/R per data class (frozen test split) published.
- [ ] **`go test -fuzz`** on the MCP and SSE parsers (and every other parser in A§14.3): campaign complete, crashers fixed, corpora committed.
- [ ] **1 M lineage events/s into ClickHouse** with raw results (Phase 4 numbers re-run on the final commit).
- [ ] `DESIGN.md`, `BENCHMARKS.md`, `FAILURES.md`, write-up published; **claims ledger 100 % green** (every number in README/resume traces to a raw file).
- [ ] Reproducibility drill passed.

---

## 10. Phase 6 — Buffer, hardening, stretch

**Effort:** ≈ 30 h of flex. Order of use:

1. **Slippage from any phase** (default consumer).
2. **Hardening backlog** from Phase 5 findings: top-N risks from the failure report; limits tuning; ergonomics of `twctl`.
3. **Stretch (only if buffer remains, in this order):** `hold`-mode approvals; Responses API breadth; spotlighting action; WebSocket reject-with-metrics → inspected transport; Anthropic Messages adapter; format-preserving tokenization option; OSS-Fuzz-style continuous fuzzing; Helm chart/Kustomize; minimal admin UI; contribute an upstream fix discovered during the build (e.g., in an MCP SDK or ClickHouse client) with a regression test.

---

## 11. Test strategy

| Layer | What | Tools | Gate |
|---|---|---|---|
| **Unit** | Validators, normalizer, AC, policy compiler, token vault, WAL | `go test -race`, table tests, published vectors | CI, every PR |
| **Property** | Chunk-invariance, idempotence, monotonicity, round-trips (tokenize/detokenize), splice correctness | `rapid` | CI |
| **Differential** | SSE vs reference parser; JSON scan vs `encoding/json`; stream scanner vs whole-text scanner; cached vs uncached detections | custom harnesses in `testkit` | CI + fuzz |
| **Fuzz** | All parsers & protocol decoders (A§14.3) | `go test -fuzz`, seed corpora from real shapes | 30 s smoke per PR; 30 min nightly; 8 h per release |
| **Golden** | Policy decisions, wire-level rewriter outputs, error bodies | golden files with review-diff | CI |
| **Integration** | Gateway + `twmock` + ClickHouse via Compose; SDK compatibility matrix | Docker Compose, official SDKs | CI (nightly for SDK matrix) |
| **Scenario/e2e** | Agent-loop lineage scenarios with exact expected rows; trifecta; approvals | scenario DSL in `testkit` | CI |
| **Ground-truth stream e2e** | Leak count at client with injected values at random splits | `twload` + `twmock` | CI small; nightly large |
| **Evaluation** | P/R per class, FP/1K, stream-leak rate | `tweval` | CI gate on dev; manual test-split |
| **Security** | Smuggling, header leak, alg confusion, tenant isolation, log/trace canary scan, privacy grep on stores | dedicated suites | CI |
| **Performance** | Microbench gates; load tests; ablations | `benchstat`, `twload` | CI micro; rig for macro |
| **Chaos** | F-01…F-34 | toxiproxy, netem, dm-flakey, signals | nightly subset; full in Phase 5 |
| **Soak** | 4–8 h at 70 % of knee with churn and random aborts; flat memory/goroutines/FDs | `twload` | before release |

**Key invariant tests (named so they cannot be forgotten):**

1. `TestStreamChunkInvariance` — output and detections independent of partitioning.
2. `TestNoClearBytesAtClient` — strict-tier values never reach the client in any chunking mode.
3. `TestInspectWhatYouForward` — forwarded bytes are exactly scanner-validated bytes (differential vs reference).
4. `TestHeaderBodyEquality` — MCP header/body mismatch is always rejected.
5. `TestFailClosedSevere` — injected detector panic never yields clear severe-class bytes.
6. `TestDataPathIndependentOfLineage` — ClickHouse down/slow does not change request/stream latency distribution beyond tolerance.
7. `TestTenantIsolation` — overlapping values across tenants never cross-influence cache, tokens, tags, approvals.
8. `TestNoSecretsInTelemetry` — canary values never appear in logs, traces, metrics, ClickHouse.
9. `TestGovernorHoldsSLO` — with stage 3 throttled, request p99 ≤ 10 ms.
10. `TestTokenNeverRedetected` — tokenizer output does not trigger detectors.

---

## 12. Benchmark protocol and pre-registration

### 12.1 Pre-registration template (`bench/PLAN.md`)

Committed **before** final runs; changing it afterwards requires a dated amendment section (so post-hoc metric shopping is visible).

```
Hypothesis:            e.g. "At W1/20K req/s the gateway adds ≤ 5 ms p99 on the stream path (excluding hold-back)."
Workload:              W1 (README §6.3) with seeds; sensitivity variants
Systems under test:    commit SHA, Go version, build flags, config hash
Hardware:              VM types, kernel, governor, sysctls (env.json)
Metrics:               added latency (request path / per event), hold-back, throughput, CPU/core-s per event,
                       memory per stream, drops/degraded rate, GC pause + sched latency
Success criteria:      numeric, per metric
Runs:                  ≥ 5 per point; warm-up duration; run duration; cool-down
Analysis:              merge HdrHistograms across runs; report p50/p99/p99.9/max; 95% CI over per-run values (bootstrap)
Invalidation rules:    run discarded iff (generator CPU > 60%) or (generator jitter p99 > 200µs) or (rig noise canary fails)
Ablations:             list
```

### 12.2 Run procedure (checklist in `bench/RUNBOOK.md`)

1. `make rig-up`; verify clocks (chrony offset < 100 µs), governor, THP, ulimits, cpusets, IRQ affinity.
2. **Noise canary:** a fixed CPU/network microbenchmark on each VM; abort if > 5 % off the stored baseline.
3. Warm up (JIT-less but caches, pools, connection pools, GC): 60 s at target load, discard.
4. Measure: ≥ 5 runs × ≥ 5 min per point, randomized point order across the session (to decorrelate drift).
5. Collect: raw HdrHistograms, per-event CSV samples (decimated), `pprof`/trace snapshots at the knee, Prometheus snapshots, `env.json`.
6. Cross-check: **external (load generator) p99 vs internal (`tw_*` histogram) p99** must agree within the join tolerance; a discrepancy is a finding, not noise.
7. `make rig-down`; log cost in `bench/COSTS.md`.

### 12.3 Statistical rules

- **Never average percentiles.** Merge histograms; compute percentiles on the merged data. For run-to-run variability, report the distribution of per-run p99.
- Report **p50, p99, p99.9, max**, count, and offered vs achieved rate; show the **latency-vs-load curve with the knee**, not a single point.
- State coordinated-omission correction used (open loop, intended-time stamping) in every chart caption.
- Charts regenerate from raw files with one script; chart captions auto-include run IDs and commit SHA.

---

## 13. Claims ledger

A table checked by CI (`scripts/check-claims`): every numeric claim in README, BENCHMARKS, DESIGN, the write-up, or the resume line has a row; the check fails if a claim has no source file or if the value no longer matches the file.

| Claim ID | Text as published | Source file (under `bench/results/…` or `eval/results/…`) | Extraction command | Run ID | Commit | Status |
|---|---|---|---|---|---|---|
| C-001 | "p99 added latency X ms at 20 K req/s (W1)" | `…/summary.json` | `jq '.w1.added_p99_ms'` | | | ☐ |
| C-002 | "1 M lineage events/s sustained 10 min, 0 dropped" | `…/lineage/summary.json` | | | | ☐ |
| C-003 | "Recall R% / Precision P% on PCI.PAN (adversarial, frozen test split)" | `eval/results/test-<hash>.json` | | | | ☐ |
| C-004 | "N fuzz targets, H CPU-hours, M crashers found/fixed" | `fuzz/results/campaign.json` | | | | ☐ |
| … | | | | | | |

Resume/README placeholders use the form `[measured:C-001]` so an unfilled claim is grep-able and cannot ship.

---

## 14. Risk register and the ordered cut list

### 14.1 Risk register (live; reviewed every Wednesday)

| ID | Risk | Likelihood | Impact | Trigger | Response |
|---|---|---|---|---|---|
| R1 | 20 K req/s at W1 unreachable on the rig | Medium | High (headline) | Phase 0 floor × overhead model says < 20 K | Larger gateway VM; h2 upstream; coalescing window; else publish knee |
| R2 | Stage-3 model misses latency | Medium | Medium | WP3.4 gate | Smaller model; async injection |
| R3 | T3 stream leakage unacceptable | Medium | Medium | WP3.2/3.5 numbers | Promote class to `strict_tail_hold`; publish cost |
| R4 | SDK incompatibility with `empty-delta` | Low–Med | Medium | WP2.3 matrix | `coalesce`; document |
| R5 | MCP spec drift | Medium | Medium | Day-1 re-read in P2; spec changelog watch | Adapter isolation; version-pinned conformance |
| R6 | Eval-set overfit/optimism | Medium | High (credibility) | Large dev/test gap, or perfect scores | Blind mini-set; per-slice reporting; hard negatives |
| R7 | ClickHouse tuning at 1 M/s | Medium | Medium | WP1.6 probe < 1 M | Tuning plan in P1; fallback second node documented |
| R8 | Schedule overrun | **High** | Medium | End-of-P2 recalibration shows > 15 % over | Cut list §14.2 |
| R9 | GC/scheduler tail at 26 K streams | Medium | Medium | p99.9 outliers in P2 benchmarks | Allocation gates; GC A/B; forensics |
| R10 | Vault/KMS scope creep | Low | Low | — | Local master key + HKDF only; KMS as documented extension |
| R11 | Rig cost overrun | Low–Med | Low | `COSTS.md` trend | Shorter runs, fewer ablations, laptop for shape |
| R12 | Burnout/context loss | Medium | High | — | Weekly status note; ADRs as memory; phase briefs |

### 14.2 Ordered cut list (use only if the end-of-Phase-2 recalibration says you are over budget)

Never cut anything the brief names. Cut **in this order**, stopping as soon as the schedule fits:

| # | Cut | Saves | What you lose | How it is disclosed |
|---|---|---|---|---|
| **C1** | Responses API breadth (keep final-object re-inspection and hosted-MCP bypass detection only) | ≈ 3 h | Delta-level streaming inspection for Responses | README: "Responses API: bypass detection and final-output inspection" |
| **C2** | SHINGLE (document-level) lineage | ≈ 4 h | Partial-copy linking for record-level sources | Listed as gap in A§10.4 and in the write-up |
| **C3** | Hash-chained audit + synchronous group-commit WAL (keep WAL spill and audit event emission) | ≈ 4 h | Tamper-evidence and crash-durable block records | FAILURES.md "audit durability: best-effort" |
| **C4** | History hash-chain session IDs (keep explicit header, MCP session, idle-window) | ≈ 3 h | Session continuity for stateless clients without headers | Documented limitation + SDK header recipe |
| **C5** | Legacy MCP resumption/GET-stream handling (keep `initialize`, sessions, POST path) | ≈ 3 h | Resume-after-reconnect for `2025-11-25` servers | README MCP matrix |
| **C6** | `S3-INJECT` classifier (keep L0, L1, L3) | ≈ 6 h | Paraphrase-robust injection scoring | Injection eval published without L2 |
| **C7** | Approval webhooks/RBAC beyond CLI (keep `retry_with_grant` core + CLI approve) | ≈ 3 h | Production-grade approval workflow | README "approvals: API + CLI" |

Total available ≈ 26 h, which moves Option A (≈ 298 h) to Option B (≈ 272 h). It does **not** make the brief's 5 weeks achievable (§1.2, option D). Cuts are **recorded as ADR amendments** with the date and reason, so they read as deliberate engineering, not omission.

---

## 15. Dependencies (candidates, with selection criteria)

**Rule:** minimize direct dependencies on the data path; every dependency is justified in an ADR line, version-pinned, covered by `govulncheck`, and its maintenance status and licence **verified at selection time** (this table lists candidates, not endorsements).

| Need | Candidate(s) | Criteria / notes |
|---|---|---|
| HTTP/2 | stdlib `net/http` + `golang.org/x/net/http2` (h2c) | Prefer stdlib; confirm h2c server behaviour and flush semantics in WP0.4 |
| YAML (strict) | `goccy/go-yaml` or `yaml.v3` with `KnownFields` | Strict unknown-field rejection, line numbers in errors |
| JWT/JWKS | `golang-jwt/jwt/v5` or `lestrrat-go/jwx` | Algorithm allow-list, key rotation, active maintenance |
| Hashing | `zeebo/xxh3` (cache key), stdlib `crypto/hmac`+`sha256`, `golang.org/x/crypto/hkdf`, `chacha20poly1305`/`aes-gcm` | Non-crypto hash only for cache keys; fingerprints use HMAC |
| Policy expressions | `google/cel-go` | Cost limits; confirm eval ns/op on target expressions |
| ClickHouse | `ClickHouse/ch-go` (insert path), `clickhouse-go/v2` (query path in `twctl`) | ch-go column API; verify dedup-token support in the chosen version |
| Metrics/Tracing | `prometheus/client_golang`, `go.opentelemetry.io/otel` | Native histograms + exemplars availability |
| Latency histograms | `HdrHistogram/hdrhistogram-go` | Merge support; 1 µs resolution |
| Cache | `maypok86/otter` (W-TinyLFU) or own sharded LRU | Benchmark; byte-budget eviction needed |
| Property tests | `pgregory.net/rapid` | Shrinking quality |
| Leak checks | `go.uber.org/goleak` | Used in every integration test |
| Fault injection | Shopify `toxiproxy`, `tc netem`, `dm-flakey` | Rig tooling, not linked into the binary |
| ONNX (sidecar only) | ONNX Runtime + a Go binding (e.g., `yalue/onnxruntime_go`) | Sidecar process only; verify binding maintenance and ORT version pinning |
| Load/traces | BurstGPT trace (public) | Verify schema and licence at import |

---

## 16. The first ten working days, task by task

**Day 1**
- Repo, `go.mod` (Go 1.26.x), CI skeleton, Makefile targets, Dockerfile, conventions doc, ADR template; import ARCHITECTURE/README/this plan into `docs/`.
- **Spec re-read (1 h):** MCP latest revision + changelog; OpenAI chat/responses streaming docs; write `docs/mcp-notes.md` and `docs/openai-notes.md` with exact header/event names and the revision strings you will target.
- `eval/classes.yaml` skeleton.

**Day 2**
- `twmock` LLM mock: chat non-stream + SSE with shape controls; ground-truth injection for PAN and one secret format; chunking modes; emit-timestamp log.
- Start `twload` open-loop scheduler + HdrHistogram output; env capture.

**Day 3**
- Finish `twload` (stream timestamps, ground-truth checker, BurstGPT importer, modes). **Write and pass the three self-validation tests** (coordinated omission, headroom, clock join).
- Null proxy v0 on laptop; first latency curves.

**Day 4**
- Rig IaC + runbook; **first rig session**: null-proxy floor at 5/10/20/30 K, h1 vs h2, TLS on/off; fit `c_e`, `c_r`; record knee; decide R1; `make rig-down`.
- Observability baseline (metrics, dashboards, pprof). **Phase 0 exit review.**

**Day 5**
- Edge + config loader + admin listener; registry snapshot; API-key and JWT authN with tests.

**Day 6**
- Router + non-stream chat path with strict JSON scan v1; upstream client + credential brokering; header-leak and smuggling tests.

**Day 7**
- SSE decoder/encoder + streaming passthrough loop; `FuzzSSEDecoder` + reference parser; leak/slow-client tests.

**Day 8**
- JSON scanner v2 (delta paths, resumable escapes, splice API, duplicate keys); `FuzzJSONScan(Diff)`, `FuzzDeltaRewriter`; gated benchmarks.

**Day 9**
- Lineage skeleton (ring, structs, null sink), DDL v1, `ch-go` writer prototype, **ingest probe on rig C**; request events and stage timers.

**Day 10**
- SDK compatibility matrix (Python/TS), parse-only performance run on the rig vs null-proxy floor, fix top hotspots; **Phase 1 exit review**; freeze metrics names and config v0.9; write Phase 2 brief.

---

## 17. Definition of done for v0.1

A release candidate is "done" when **all** of the following hold:

**Functional (brief)**
- [ ] OpenAI-compatible (chat, stream/non-stream; Responses subset) and MCP (both revisions) endpoints work with official SDKs.
- [ ] SSE inspection with bounded hold-back; chunk-invariance proven; no whole-response buffering by default.
- [ ] Per-agent identity (JWT/mTLS/API key) and tool scoping with `tools/list` filtering and pinning.
- [ ] Cascade: stage 1 validators, stage 2 dictionary/entity + session literals, stage 3 ONNX sidecar on the uncertain band under a budget governor.
- [ ] Policy: `allow|redact|tokenize|require_approval|block` per class × agent × destination; `enforce|monitor|shadow`; signed hot reload; failure matrix tested.
- [ ] Injection defence L0–L3 with provenance; trifecta rule demonstrated.
- [ ] Lineage: tags at sources, EXACT flows at sinks, ClickHouse tables, `twctl` investigations, privacy test passing.

**Proof (brief)**
- [ ] 20 K req/s at W1 (or measured knee as the claim) with added-latency percentiles; CIs; reproducible.
- [ ] Per-class P/R on the frozen adversarial test split; FP/1K reported.
- [ ] Fuzz campaign complete for every parser; crashers fixed.
- [ ] 1 M lineage events/s, 10 min, 0 dropped.

**Evidence**
- [ ] `DESIGN.md`, `BENCHMARKS.md`, `FAILURES.md`, write-up published; claims ledger green; reproducibility drill passed.

**Operational**
- [ ] Canary probes running; dashboards provisioned; runbook for the top ten alerts; `make repro` documented.

**Honesty**
- [ ] README states what is not claimed (A§10.4, README §3); results labelled synthetic where applicable; described as an independent open-source project.
