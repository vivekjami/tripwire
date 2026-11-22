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
