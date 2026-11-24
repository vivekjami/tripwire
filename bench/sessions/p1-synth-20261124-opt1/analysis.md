# Phase 1 parse-only performance, session `p1-synth-20261124-opt1` (SYNTHETIC local rig: shape only, not publishable)

Gateway = auth + strict parse + SSE decode + delta scan + request events, **no detectors**. Floor = null proxy. Both pinned to the same 2 cores.

## Knee sweep (3 runs per rate; healthy = merged event_delay p99 <= 5 ms and achieved >= 98 % of offered)
```
null proxy:
   req/s   runs  ev p99 (µs)   achieved  healthy

gateway:
   req/s   runs  ev p99 (µs)   achieved  healthy
```

## Comparison at 70 % of the null knee (210 req/s) and at the knee (300 req/s), 5 runs per cell

### event_delay
| point | runs (valid) | offered req/s | event_delay merged p50 | p99 | p99.9 | max (µs) | per-run p99 mean ± 95% CI (µs) | SUT cores | gen CPU |
|---|---|---|---|---|---|---|---|---|---|
| p1-synth-20261124-opt1-cmp-direct-L210 | 5 (0) | 210 | 64 | 256 | 568 | 5963 | 254 ± 18 | 0.00 | 21% |
| p1-synth-20261124-opt1-cmp-direct-L300 | 5 (0) | 300 | 60 | 330 | 2385 | 17807 | 333 ± 32 | 0.00 | 30% |
| p1-synth-20261124-opt1-cmp-gw-L210 | 5 (0) | 210 | 259 | 1519 | 14967 | 37599 | 1723 ± 800 | 0.74 | 27% |
| p1-synth-20261124-opt1-cmp-gw-L300 | 5 (0) | 300 | 455 | 9719 | 21679 | 52127 | 9893 ± 1490 | 1.12 | 40% |
| p1-synth-20261124-opt1-cmp-null-L210 | 5 (0) | 210 | 225 | 979 | 10511 | 37183 | 993 ± 340 | 0.64 | 26% |
| p1-synth-20261124-opt1-cmp-null-L300 | 5 (0) | 300 | 302 | 3513 | 23007 | 56991 | 3808 ± 1353 | 0.97 | 38% |

### request_total
| point | runs (valid) | offered req/s | request_total merged p50 | p99 | p99.9 | max (µs) | per-run p99 mean ± 95% CI (µs) | SUT cores | gen CPU |
|---|---|---|---|---|---|---|---|---|---|
| p1-synth-20261124-opt1-cmp-direct-L210 | 5 (0) | 210 | 565759 | 622591 | 641535 | 646655 | 622181 ± 284 | 0.00 | 21% |
| p1-synth-20261124-opt1-cmp-direct-L300 | 5 (0) | 300 | 565759 | 626175 | 646655 | 666623 | 626175 ± 0 | 0.00 | 30% |
| p1-synth-20261124-opt1-cmp-gw-L210 | 5 (0) | 210 | 566271 | 626175 | 642047 | 681983 | 625868 ± 1595 | 0.74 | 27% |
| p1-synth-20261124-opt1-cmp-gw-L300 | 5 (0) | 300 | 567295 | 628223 | 649215 | 671743 | 628223 ± 1101 | 1.12 | 40% |
| p1-synth-20261124-opt1-cmp-null-L210 | 5 (0) | 210 | 566271 | 626175 | 642047 | 647167 | 624229 ± 2220 | 0.64 | 26% |
| p1-synth-20261124-opt1-cmp-null-L300 | 5 (0) | 300 | 566271 | 626687 | 647167 | 678399 | 626892 ± 348 | 0.97 | 38% |

### Added latency of the gateway over the null proxy (merged histograms, runs 1-5 pooled by twagg; r1 shown by twload diff)
```
load 210 req/s: gateway - null
event_delay (test − base):
  p50    base=210µs     test=264µs     added=54µs
  p90    base=410µs     test=535µs     added=125µs
  p99    base=830µs     test=1.43ms    added=603µs
  p99.9  base=16.72ms   test=15.05ms   added=-1664µs
time_to_first_event (test − base):
load 300 req/s: gateway - null
event_delay (test − base):
  p50    base=303µs     test=442µs     added=139µs
  p90    base=708µs     test=2.12ms    added=1.41ms
  p99    base=1.98ms    test=8.89ms    added=6.91ms
  p99.9  base=12.76ms   test=13.46ms   added=704µs
time_to_first_event (test − base):
```

## Criteria
- p99 added event latency over the null proxy at 70% of knee (210 req/s): **540 us** (gateway 1519 us vs null 979 us); criterion <= 1000 us -> PASS
- p50 added: 34 us
- SUT CPU at 210 req/s: null 0.64 cores, gateway 0.74 cores (x1.16)
- runs flagged valid: 0/30 (a virtualised host: every number here is shape-only)
