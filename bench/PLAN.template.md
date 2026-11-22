# Benchmark pre-registration (template)

Copy to `bench/PLAN.md` and commit it **before** any final run (IMPLEMENTATION_PLAN §12.1). After that, changes require a dated *Amendment* section so post-hoc metric shopping is visible.

```
Hypothesis:          e.g. "At W1 / 20K req/s the gateway adds <= 5 ms p99 on the stream path (excluding hold-back)."
Workload:            W1 (README §6.3) with seeds; sensitivity variants
Systems under test:  commit SHA, Go version, build flags, config hash
Hardware:            VM types, kernel, governor, sysctls (env.json)
Metrics:             added latency (request path / per event), hold-back, throughput, CPU core-s per request and per event,
                     memory per stream, drops/degraded rate, GC pause + scheduler latency
Success criteria:    numeric, per metric
Runs:                >= 5 per point; warm-up duration; run duration; cool-down; randomized point order
Analysis:            merge HdrHistograms across runs; report p50/p99/p99.9/max; 95% CI over per-run values (bootstrap)
Invalidation rules:  run discarded iff (generator CPU > 60%) or (dispatch-lag p99 > 200us) or (undispatched arrivals > 0)
                     or (rig noise canary fails). These are computed by twload and recorded in summary.json.
Ablations:           message cache off, hold-back off, stage 3 off, lineage off, GC A/B (GOEXPERIMENT=nogreenteagc), coalesce_window 0 vs 1ms
```
