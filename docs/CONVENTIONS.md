# Engineering conventions

Rules every PR is reviewed against (IMPLEMENTATION_PLAN §2, WP0.1). They exist
because Tripwire is an inline security component that parses hostile input at
high rate; each rule closes a specific failure class.

## Layout
`cmd/<binary>` is thin (flags → wiring). Logic lives in `internal/<pkg>`; package layout follows README §9. Data-path packages (`sse`, `jsonscan`, `detect`, `mcp`, `oai`) never import harness packages (`mock`, `load`, `groundtruth`).

## Errors
Wrap with `%w` and context (`fmt.Errorf("read body: %w", err)`); never compare error strings; classify at boundaries (see `load.classifyErr`). A function that can fail on hostile input returns an error: **no `panic` for input-dependent conditions.**

## Panics and goroutines
- No panic may escape a goroutine we start. Every goroutine that handles request data recovers at its top and applies the **explicit fail behaviour** for the class involved (ARCHITECTURE §7.4); the process survives.
- Every goroutine has an owner and an exit condition (context, channel close, or deadline). New integration tests use `goleak`.

## Context and deadlines
Every blocking call takes a `context.Context` or has a deadline: network I/O, upstream calls, locks held across I/O (don't), classifier calls. Request-scoped deadlines derive from the budget governor (§6.6). Slow clients are bounded by per-write deadlines (`http.ResponseController`), never by trusting the peer.

## Limits
Every input has a bound **before** it has a parser: bytes, depth, count, time, state. Defaults live in one place (ARCHITECTURE §14.2) and are configurable but never unbounded. A limit violation is an error with a metric, not a truncation.

## Allocation and the hot path
Hot packages (`internal/{sse,jsonscan,detect}`): offset-based scanning over `[]byte`, pooled buffers (return only buffers under a size cap), no `fmt`/`reflect`/`encoding/json` on the per-event path. `make escape-check` fails a PR that adds a heap escape; `-benchmem` results are in the PR for any hot-path change. Targets: ≤ 1 alloc/event steady state, ≤ 40 allocs/request.

## Logging and telemetry
Structured `slog` through `obs.NewLogger`, which **drops any field not on the allow-list** (`internal/obs`). **Never log payload bytes, detected values, tokens or credentials**; log classes, counts, ids, sizes and timings. Adding a field means adding it to the allow-list in review. A CI canary test (Phase 4, `TestNoSecretsInTelemetry`) injects known secrets and fails if they appear in logs, traces or metrics.

## Metrics
Prometheus names `tw_<area>_<what>_<unit>`; counters end `_total`; durations are seconds (`_seconds`) in Prometheus, microseconds in result files. Labels are **bounded**: never user data, never per-request ids; tenant label only on aggregated counters. Names and labels freeze at the end of Phase 1; dashboards depend on them.

## Determinism
Anything used to generate test data takes an explicit seed and uses `math/rand/v2` PCG (`gen.NewRand`). `math/rand` is for tests and mocks only, **never** for security material (fingerprints, tokens, keys use `crypto/*`; gosec G404 is excluded for exactly this reason).

## Fuzzing
A parser or decoder PR includes its `Fuzz*` target (`scripts/fuzz-smoke.sh` discovers them). Crashers become `testdata/fuzz` regression tests. Differential targets compare against a slow, obviously-correct reference kept in `testkit`.

## Numbers
No performance or accuracy figure is typed by hand into any document. Numbers come from `bench/results/<run-id>/` or `eval/results/` and are cited by run id and commit. Anything tagged `[hypothesis]` in ARCHITECTURE.md stays tagged until a measured value replaces it. Laptop/WSL2 runs are **shape-only** and say so in `env.json`.

## Dependencies
Few, justified, pinned, `govulncheck`-clean. Prefer the standard library when it has caught up (e.g. cleartext HTTP/2 via `http.Protocols` instead of `x/net/http2/h2c`; see AMD-004). The data-path binary is `CGO_ENABLED=0`.

## Commits and PRs
Trunk-based, small PRs (≲ 400 changed lines excluding generated/test data), PR template checklist filled in. Deviations from ARCHITECTURE are recorded in `docs/adr/AMENDMENTS.md` **in the same PR**.
