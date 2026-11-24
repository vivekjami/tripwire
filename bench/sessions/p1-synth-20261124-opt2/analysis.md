# Phase 1 parse-only performance, session `p1-synth-20261124-opt2` (SYNTHETIC local rig: shape only, not publishable)

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
| p1-synth-20261124-opt2-cmp-direct-L210 | 5 (0) | 210 | 65 | 282 | 2459 | 8655 | 283 ± 54 | 0.00 | 22% |
| p1-synth-20261124-opt2-cmp-direct-L300 | 5 (0) | 300 | 61 | 442 | 4727 | 17807 | 448 ± 263 | 0.00 | 32% |
| p1-synth-20261124-opt2-cmp-gw-L210 | 5 (0) | 210 | 259 | 1271 | 6727 | 29759 | 1305 ± 296 | 0.76 | 28% |
| p1-synth-20261124-opt2-cmp-gw-L300 | 5 (0) | 300 | 485 | 9919 | 24447 | 63103 | 9693 ± 1761 | 1.14 | 40% |
| p1-synth-20261124-opt2-cmp-null-L210 | 5 (0) | 210 | 240 | 2679 | 17551 | 52127 | 3247 ± 4851 | 0.68 | 27% |
| p1-synth-20261124-opt2-cmp-null-L300 | 5 (0) | 300 | 319 | 17839 | 44895 | 78527 | 9895 ± 18268 | 1.01 | 38% |

### request_total
| point | runs (valid) | offered req/s | request_total merged p50 | p99 | p99.9 | max (µs) | per-run p99 mean ± 95% CI (µs) | SUT cores | gen CPU |
|---|---|---|---|---|---|---|---|---|---|
| p1-synth-20261124-opt2-cmp-direct-L210 | 5 (0) | 210 | 565759 | 625663 | 641535 | 646655 | 623513 ± 2437 | 0.00 | 22% |
| p1-synth-20261124-opt2-cmp-direct-L300 | 5 (0) | 300 | 565759 | 626175 | 646655 | 666623 | 626175 ± 449 | 0.00 | 32% |
| p1-synth-20261124-opt2-cmp-gw-L210 | 5 (0) | 210 | 566271 | 626687 | 642047 | 653823 | 625868 ± 1938 | 0.76 | 28% |
| p1-synth-20261124-opt2-cmp-gw-L300 | 5 (0) | 300 | 567295 | 628223 | 654847 | 689663 | 628633 ± 1449 | 1.14 | 40% |
| p1-synth-20261124-opt2-cmp-null-L210 | 5 (0) | 210 | 566271 | 626175 | 642047 | 647679 | 624127 ± 2659 | 0.68 | 27% |
| p1-synth-20261124-opt2-cmp-null-L300 | 5 (0) | 300 | 566783 | 632831 | 669695 | 709119 | 633036 ± 17982 | 1.01 | 38% |

### Added latency of the gateway over the null proxy (merged histograms, runs 1-5 pooled by twagg; r1 shown by twload diff)
```
load 210 req/s: gateway - null
event_delay (test − base):
  p50    base=237µs     test=272µs     added=35µs
  p90    base=491µs     test=564µs     added=73µs
  p99    base=2.23ms    test=1.34ms    added=-888µs
  p99.9  base=8.94ms    test=9.44ms    added=504µs
time_to_first_event (test − base):
load 300 req/s: gateway - null
event_delay (test − base):
  p50    base=330µs     test=480µs     added=150µs
  p90    base=936µs     test=2.53ms    added=1.59ms
  p99    base=4.47ms    test=9.55ms    added=5.08ms
  p99.9  base=13.53ms   test=24.69ms   added=11.16ms
time_to_first_event (test − base):
```

## Criteria
- p99 added event latency over the null proxy at 70% of knee (210 req/s): **-1408 us** (gateway 1271 us vs null 2679 us); criterion <= 1000 us -> PASS
- p50 added: 19 us
- SUT CPU at 210 req/s: null 0.68 cores, gateway 0.76 cores (x1.13)
- runs flagged valid: 0/30 (a virtualised host: every number here is shape-only)
