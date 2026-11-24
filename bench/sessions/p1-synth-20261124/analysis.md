# Phase 1 parse-only performance, session `p1-synth-20261124` (SYNTHETIC local rig: shape only, not publishable)

Gateway = auth + strict parse + SSE decode + delta scan + request events, **no detectors**. Floor = null proxy. Both pinned to the same 2 cores.

## Knee sweep (3 runs per rate; healthy = merged event_delay p99 <= 5 ms and achieved >= 98 % of offered)
```
null proxy:
   req/s   runs  ev p99 (µs)   achieved  healthy
     100      3          403      98.2%     true
     200      3          953      98.9%     true
     300      3         2261     100.9%     true
     400      3         5919     100.8%    false
     500      3        10863     100.3%    false
     600      3        14103     100.4%    false
300

gateway:
   req/s   runs  ev p99 (µs)   achieved  healthy
     100      3          555      98.2%     true
     200      3         1378      98.9%     true
     300      3       102719     100.9%    false
     400      3        29615     100.8%    false
     500      3        40799     100.3%    false
     600      3        49151     100.4%    false
200
```

## Comparison at 70 % of the null knee (210 req/s) and at the knee (300 req/s), 5 runs per cell

### event_delay
| point | runs (valid) | offered req/s | event_delay merged p50 | p99 | p99.9 | max (µs) | per-run p99 mean ± 95% CI (µs) | SUT cores | gen CPU |
|---|---|---|---|---|---|---|---|---|---|
| p1-synth-20261124-cmp-direct-L210 | 5 (0) | 210 | 63 | 249 | 850 | 10239 | 249 ± 11 | 0.00 | 20% |
| p1-synth-20261124-cmp-direct-L300 | 5 (0) | 300 | 61 | 2883 | 14247 | 34047 | 2082 ± 4878 | 0.00 | 31% |
| p1-synth-20261124-cmp-gw-L210 | 5 (0) | 210 | 269 | 2157 | 17455 | 63839 | 3020 ± 3386 | 0.75 | 27% |
| p1-synth-20261124-cmp-gw-L300 | 5 (0) | 300 | 526 | 12063 | 29375 | 60415 | 12026 ± 2590 | 1.14 | 40% |
| p1-synth-20261124-cmp-null-L210 | 5 (0) | 210 | 225 | 1858 | 14519 | 49055 | 2030 ± 2092 | 0.63 | 26% |
| p1-synth-20261124-cmp-null-L300 | 5 (0) | 300 | 309 | 2761 | 13047 | 34239 | 2823 ± 663 | 0.97 | 38% |

### request_total
| point | runs (valid) | offered req/s | request_total merged p50 | p99 | p99.9 | max (µs) | per-run p99 mean ± 95% CI (µs) | SUT cores | gen CPU |
|---|---|---|---|---|---|---|---|---|---|
| p1-synth-20261124-cmp-direct-L210 | 5 (0) | 210 | 565759 | 622079 | 641535 | 646655 | 621977 ± 284 | 0.00 | 20% |
| p1-synth-20261124-cmp-direct-L300 | 5 (0) | 300 | 565759 | 628223 | 658943 | 726015 | 629452 ± 9096 | 0.00 | 31% |
| p1-synth-20261124-cmp-gw-L210 | 5 (0) | 210 | 566271 | 626175 | 642047 | 694271 | 624332 ± 2229 | 0.75 | 27% |
| p1-synth-20261124-cmp-gw-L300 | 5 (0) | 300 | 567295 | 629759 | 649727 | 673791 | 629657 ± 2353 | 1.14 | 40% |
| p1-synth-20261124-cmp-null-L210 | 5 (0) | 210 | 566271 | 626175 | 642047 | 658943 | 624741 ± 2749 | 0.63 | 26% |
| p1-synth-20261124-cmp-null-L300 | 5 (0) | 300 | 566271 | 626687 | 647167 | 668159 | 626789 ± 284 | 0.97 | 38% |

### Added latency of the gateway over the null proxy (merged histograms, runs 1-5 pooled by twagg; r1 shown by twload diff)
```
load 210 req/s: gateway - null
event_delay (test − base):
  p50    base=214µs     test=263µs     added=49µs
  p90    base=404µs     test=513µs     added=109µs
  p99    base=766µs     test=1.08ms    added=312µs
  p99.9  base=1.89ms    test=2.66ms    added=770µs
time_to_first_event (test − base):
load 300 req/s: gateway - null
event_delay (test − base):
  p50    base=310µs     test=536µs     added=226µs
  p90    base=812µs     test=4.30ms    added=3.49ms
  p99    base=3.61ms    test=12.58ms   added=8.98ms
  p99.9  base=14.35ms   test=28.89ms   added=14.54ms
time_to_first_event (test − base):
```

## Criteria
- p99 added event latency over the null proxy at 70% of knee (210 req/s): **299 us** (gateway 2157 us vs null 1858 us); criterion <= 1000 us -> PASS
- p50 added: 44 us
- SUT CPU at 210 req/s: null 0.63 cores, gateway 0.75 cores (x1.18)
- runs flagged valid: 1/66 (a virtualised host: every number here is shape-only)
