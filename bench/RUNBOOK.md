# Benchmark runbook (rig sessions)

Procedure for every published number (IMPLEMENTATION_PLAN §12.2). Development on a laptop is fine for correctness and *shape*; **only rig runs are citable**, and only runs with `"valid": true`.

## Rig
3 VMs rented by the hour (`deploy/rig/README.md`): **A** twload + twmock (disjoint core sets), **B** gateway (twnull in Phase 0) + twclf, **C** ClickHouse + Prometheus + Grafana + Tempo. A session starts with `make rig-up` and **ends with `make rig-down` plus a manual check that no resources remain**; log the session in `COSTS.md`.

## Pre-flight (every session, in order; abort on any failure)
1. `make rig-up`; confirm `env.json` on each VM: governor `performance`, THP `never`, `nofile` ≥ 1,048,576, sysctl profile applied (`deploy/sysctl/99-tripwire.conf`).
2. **Clock sync:** `chronyc tracking`: offset < 100 µs on all three (the emit/receive join is same-host, but trace stamps and Prometheus are not).
3. **Timer probe on VM A:** `twload timer`. Choose `--spin-margin` above the p99 overshoot of the ~1 ms sleep (WSL2 laptop: 441 µs → default 1.5 ms is conservative; bare VMs are expected to need far less. This is `[hypothesis]` until measured).
4. **Noise canary:** a fixed CPU + loopback-network microbenchmark on each VM; abort if > 5 % off the stored baseline (store the first clean one in `bench/noise-baseline.json`; not yet captured).
5. **Harness self-validation, strict:** on VM A, `TW_HEADROOM_RATE=30000 make selfcheck`. All four checks must pass without `TW_SELFCHECK_RELAXED`: coordinated-omission contrast, generator headroom (CPU < 60 %, dispatch-lag p99 < 200 µs at 30 K req/s), clock join (±50 µs), mock emission jitter.
6. Warm up: 60 s at target load, discarded.

## Measure
- ≥ 5 runs × ≥ 5 min per point; randomize point order across the session (decorrelates drift).
- `twload run … -sut-metrics http://<B>:<admin>/metrics -mock-stats http://<A>:9000/_tw/stats -ground-truth … -emit-log … -emit-sample 0.05 -check-sample 0.05`. Use the **same** `-emit-sample` on twmock and twload.
- Sweep events/response (16, 64, 256) **and** rate, so `twfit` can separate `c_r` from `c_e` (the Phase 0 laptop run varied events only; rate-variation is needed for a well-conditioned `c_r`).
- Collect: `bench/results/<run-id>/`, pprof/trace snapshots at the knee, Prometheus snapshot.

## Cross-checks
- External p99 (twload) vs internal (`tw_*` histograms, from Phase 1) must agree within the join tolerance; a discrepancy is a finding, not noise.
- A run with `valid=false` is discarded, never "mostly fine".

## Analysis rules
Merge HdrHistograms across runs (never average percentiles); report p50/p99/p99.9/max with offered vs achieved rate; show the latency-vs-load curve with the knee; state the coordinated-omission correction (open loop, intended-time stamping) in every chart caption. "Added latency" = `twload diff` of the same measurement through the proxy vs direct (percentile-wise difference; an approximation of the distribution of differences, stated beside every chart).

## Synthetic local rig (no cloud needed)
`make rig-local S=<name>` runs this whole procedure on one host with `deploy/rig/providers/local.sh` (generator / mock / gateway pinned to disjoint cores; throw-away CA for TLS; teardown verifies no processes, no listeners, no state dir). `make rig-local-analyze S=<name>` writes the tables. It validates the *procedure and tooling* and gives the shape of the curves; on a virtualised laptop every run is `valid=false`, so nothing from it is citable. A real rig session replaces it with `make rig-up` + the same analysis script.

## Lineage ingest probe (Phase 1, WP1.6): run this on rig C
Purpose: find the ceiling and the settings that matter *before* Phase 4 depends on 1 M rows/s.
1. Start a single ClickHouse node on rig C (record version, `config.xml` deltas and `system.settings` changes in `env.json`).
2. `twmigrate -addr <C>:9000` creates the `tw` schema (idempotent; applied migrations are checksum-locked).
3. For rate in 100 K, 250 K, 500 K, 750 K, 1 M ev/s, 5 minutes each:
   `twload run -mode lineage -sink clickhouse -ch-addr <C>:9000 -rate <rate> -duration 5m -batch-rows 100000 -writers 2 -run-id lineage-<rate>`
4. After each rate record from `system.parts` (active parts per partition), `system.merges`, `system.asynchronous_metrics` and `system.events` (`InsertedRows`, `DelayedInserts`, `RejectedInserts`) into the run directory. Success = `loss_free: true` and `committed == emitted` in `summary.json` *and* `count()` in `tw.request_events` equal to `committed`.
5. The output of the phase is **a number (sustainable rows/s) and the list of ClickHouse/pipeline settings that mattered** (block rows, flush interval, writers, `parts_to_throw_insert`, merge pool). If the ceiling is below 1 M rows/s, write the plan (batching, parts, second node, column trimming) before Phase 4.
The pipeline alone (null sink) is measured with `-sink null`; that isolates the ring and batcher from ClickHouse.

## Compatibility matrix
`scripts/compat.sh` runs curl, the third-party Go client and (when `TW_PYTHON` / `TW_NODE` + `TW_NODE_MODULES` point at interpreters with the official SDKs installed) the OpenAI Python and TypeScript SDKs against gateway -> twmock, and writes `bench/compat/<date>/matrix.md`.

## Long fuzz
`scripts/fuzz-long.sh` runs every fuzz target for `FUZZTIME` (default 10 m) and writes `bench/fuzz/<date>/summary.txt`. Phase exit criteria require >= 10 min per parser target with no findings.
