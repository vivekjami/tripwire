# Analysis of session `p0-synth-20261122` (SYNTHETIC local rig: shape only, not publishable)

## Per-event delay, direct vs null proxy (merged histograms; p99 CI is across runs)
| point | runs (valid) | offered req/s | event_delay merged p50 | p99 | p99.9 | max (µs) | per-run p99 mean ± 95% CI (µs) | SUT cores | gen CPU |
|---|---|---|---|---|---|---|---|---|---|
| p0-synth-20261122-direct-L1000 | 5 (0) | 1000 | 62 | 4971 | 13063 | 43039 | 4584 ± 3225 | 0.00 | 66% |
| p0-synth-20261122-direct-L250 | 5 (0) | 250 | 71 | 279 | 424 | 2815 | 279 ± 7 | 0.00 | 21% |
| p0-synth-20261122-direct-L500 | 5 (0) | 500 | 65 | 463 | 1768 | 7023 | 462 ± 22 | 0.00 | 41% |
| p0-synth-20261122-null-L1000 | 5 (0) | 1000 | 8983 | 36575 | 46655 | 71423 | 36517 ± 2379 | 1.20 | 56% |
| p0-synth-20261122-null-L250 | 5 (0) | 250 | 213 | 647 | 1266 | 4155 | 645 ± 43 | 0.56 | 25% |
| p0-synth-20261122-null-L500 | 5 (0) | 500 | 390 | 8495 | 13183 | 25711 | 8222 ± 1716 | 1.24 | 50% |

## Request total latency (open loop, from intended send time)
| point | runs (valid) | offered req/s | request_total merged p50 | p99 | p99.9 | max (µs) | per-run p99 mean ± 95% CI (µs) | SUT cores | gen CPU |
|---|---|---|---|---|---|---|---|---|---|
| p0-synth-20261122-direct-L1000 | 5 (0) | 1000 | 582143 | 1963007 | 3254271 | 3872767 | 1215589 ± 1202163 | 0.00 | 66% |
| p0-synth-20261122-direct-L250 | 5 (0) | 250 | 565759 | 625663 | 645631 | 656895 | 625663 ± 0 | 0.00 | 21% |
| p0-synth-20261122-direct-L500 | 5 (0) | 500 | 565759 | 625663 | 642047 | 669695 | 625663 ± 0 | 0.00 | 41% |
| p0-synth-20261122-null-L1000 | 5 (0) | 1000 | 612351 | 766975 | 860159 | 1023487 | 767487 ± 22238 | 1.20 | 56% |
| p0-synth-20261122-null-L250 | 5 (0) | 250 | 565759 | 626175 | 646143 | 657407 | 626175 ± 0 | 0.56 | 25% |
| p0-synth-20261122-null-L500 | 5 (0) | 500 | 566783 | 626687 | 646655 | 675839 | 626789 ± 532 | 1.24 | 50% |

## Dispatch lag (generator health)
| point | runs (valid) | offered req/s | dispatch_lag merged p50 | p99 | p99.9 | max (µs) | per-run p99 mean ± 95% CI (µs) | SUT cores | gen CPU |
|---|---|---|---|---|---|---|---|---|---|
| p0-synth-20261122-direct-L1000 | 5 (0) | 1000 | 158 | 12631 | 31615 | 67263 | 12652 ± 5616 | 0.00 | 66% |
| p0-synth-20261122-direct-L250 | 5 (0) | 250 | 41 | 310 | 1061 | 2439 | 318 ± 78 | 0.00 | 21% |
| p0-synth-20261122-direct-L500 | 5 (0) | 500 | 86 | 757 | 1770 | 8479 | 752 ± 59 | 0.00 | 41% |
| p0-synth-20261122-null-L1000 | 5 (0) | 1000 | 79 | 6827 | 18943 | 48767 | 6896 ± 2240 | 1.20 | 56% |
| p0-synth-20261122-null-L250 | 5 (0) | 250 | 45 | 405 | 1157 | 3255 | 409 ± 49 | 0.56 | 25% |
| p0-synth-20261122-null-L500 | 5 (0) | 500 | 67 | 1133 | 2893 | 8727 | 1153 ± 131 | 1.24 | 50% |

## Added event latency of the null proxy (percentile-wise difference of merged histograms)
```
load 1000 req/s:
event_delay (test − base):
  p50    base=65µs      test=9.50ms    added=9.44ms
  p90    base=762µs     test=24.98ms   added=24.21ms
  p99    base=3.44ms    test=38.59ms   added=35.16ms
  p99.9  base=7.98ms    test=51.71ms   added=43.73ms
time_to_first_event (test − base):
  p50    base=5.14ms    test=55.71ms   added=50.57ms
  p90    base=67.39ms   test=106.75ms  added=39.36ms
  p99    base=211.58ms  test=199.42ms  added=-12160µs
  p99.9  base=295.68ms  test=330.75ms  added=35.07ms
time_to_headers (test − base):
  p50    base=5.13ms    test=55.68ms   added=50.54ms
  p90    base=67.39ms   test=106.75ms  added=39.36ms
  p99    base=211.58ms  test=199.42ms  added=-12160µs
  p99.9  base=295.68ms  test=330.75ms  added=35.07ms
request_total (test − base):
  p50    base=579.07ms  test=615.93ms  added=36.86ms
  p90    base=649.22ms  test=677.38ms  added=28.16ms
  p99    base=783.87ms  test=780.29ms  added=-3584µs
  p99.9  base=877.57ms  test=901.12ms  added=23.55ms
load 250 req/s:
event_delay (test − base):
  p50    base=70µs      test=224µs     added=154µs
  p90    base=168µs     test=407µs     added=239µs
  p99    base=278µs     test=682µs     added=404µs
  p99.9  base=411µs     test=1.42ms    added=1.00ms
time_to_first_event (test − base):
  p50    base=384µs     test=730µs     added=346µs
  p90    base=534µs     test=1.03ms    added=498µs
  p99    base=761µs     test=1.52ms    added=755µs
  p99.9  base=1.28ms    test=2.66ms    added=1.39ms
time_to_headers (test − base):
  p50    base=381µs     test=725µs     added=344µs
  p90    base=530µs     test=1.02ms    added=494µs
  p99    base=749µs     test=1.51ms    added=760µs
  p99.9  base=1.27ms    test=2.66ms    added=1.38ms
request_total (test − base):
  p50    base=565.76ms  test=565.76ms  added=0µs
  p90    base=595.97ms  test=596.48ms  added=512µs
  p99    base=625.66ms  test=626.17ms  added=512µs
  p99.9  base=641.53ms  test=641.53ms  added=0µs
load 500 req/s:
event_delay (test − base):
  p50    base=65µs      test=367µs     added=302µs
  p90    base=202µs     test=1.39ms    added=1.19ms
  p99    base=441µs     test=6.61ms    added=6.17ms
  p99.9  base=1.88ms    test=11.04ms   added=9.15ms
time_to_first_event (test − base):
  p50    base=506µs     test=1.20ms    added=696µs
  p90    base=835µs     test=3.34ms    added=2.51ms
  p99    base=1.40ms    test=12.62ms   added=11.22ms
  p99.9  base=2.37ms    test=19.25ms   added=16.88ms
time_to_headers (test − base):
  p50    base=504µs     test=1.19ms    added=687µs
  p90    base=832µs     test=3.32ms    added=2.49ms
  p99    base=1.39ms    test=12.62ms   added=11.23ms
  p99.9  base=2.36ms    test=19.25ms   added=16.88ms
request_total (test − base):
  p50    base=565.76ms  test=566.27ms  added=512µs
  p90    base=596.48ms  test=596.99ms  added=512µs
  p99    base=625.66ms  test=626.17ms  added=512µs
  p99.9  base=642.05ms  test=642.56ms  added=512µs
```
(diff above uses run r1 of each point; the merged-histogram table is authoritative.)

## Capacity fit
Only UNSATURATED null-proxy runs enter the fit (SUT cores < 1.0): above the knee CPU is no longer proportional to work, and a fit through saturated points is meaningless (the all-runs fit gave R^2 < 0; it is kept below for transparency).
```
runs in fit: 8
run                           req/s     events/s      cores     fitted      resid
p0-synth-20261122-fit-L1000-e16-r1       1000        32948      0.949      0.946     +0.003
p0-synth-20261122-fit-L250-e16-r1        250         8245      0.247      0.237     +0.011
p0-synth-20261122-fit-L500-e16-r1        502        16521      0.462      0.474     -0.012
p0-synth-20261122-null-L250-r1        250        28980      0.576      0.558     +0.018
p0-synth-20261122-null-L250-r2        250        28980      0.569      0.558     +0.012
p0-synth-20261122-null-L250-r3        250        28980      0.543      0.558     -0.014
p0-synth-20261122-null-L250-r4        250        28980      0.548      0.558     -0.010
p0-synth-20261122-null-L250-r5        250        28980      0.551      0.558     -0.006

c_r = 435.8 µs CPU per request     c_e = 15.48 µs CPU per event     R² = 0.996 (n=8)
prediction at 20000 req/s x 64 events/response: 28.5 cores busy (1.28 M events/s)
(null-proxy floor only; the real gateway adds inspection on top. Fit from laptop runs is shape-only.)

--- for transparency: ALL null-proxy runs incl. saturated (do not use) ---

c_r = 1225.3 µs CPU per request     c_e = 1.60 µs CPU per event     R² = -0.157 (n=21)
prediction at 20000 req/s x 64 events/response: 26.6 cores busy (1.28 M events/s)
(null-proxy floor only; the real gateway adds inspection on top. Fit from laptop runs is shape-only.)
```

## Transport / TLS at the middle load (events=64)
| point | runs (valid) | offered req/s | event_delay merged p50 | p99 | p99.9 | max (µs) | per-run p99 mean ± 95% CI (µs) | SUT cores | gen CPU |
|---|---|---|---|---|---|---|---|---|---|
| p0-synth-20261122-tp-h1 | 3 (0) | 500 | 718 | 12287 | 21791 | 51423 | 12250 ± 4326 | 1.29 | 51% |
| p0-synth-20261122-tp-h2c-h2c | 3 (0) | 500 | 1216 | 105919 | 194303 | 279807 | 56223 ± 205925 | 1.30 | 51% |
| p0-synth-20261122-tp-tls-h1 | 3 (0) | 500 | 866 | 11567 | 15847 | 27519 | 11602 ± 605 | 1.33 | 55% |
| p0-synth-20261122-tp-tls-h2 | 3 (0) | 500 | 859 | 12343 | 21967 | 51775 | 12500 ± 5167 | 1.52 | 50% |
| p0-synth-20261122-tp-uph2c | 3 (0) | 500 | 554 | 6963 | 10895 | 20447 | 6980 ± 1196 | 1.25 | 55% |

| point | runs (valid) | offered req/s | request_total merged p50 | p99 | p99.9 | max (µs) | per-run p99 mean ± 95% CI (µs) | SUT cores | gen CPU |
|---|---|---|---|---|---|---|---|---|---|
| p0-synth-20261122-tp-h1 | 3 (0) | 500 | 568319 | 629759 | 647679 | 680959 | 629588 ± 7233 | 1.29 | 51% |
| p0-synth-20261122-tp-h2c-h2c | 3 (0) | 500 | 570879 | 2125823 | 2381823 | 2512895 | 1173674 ± 2348176 | 1.30 | 51% |
| p0-synth-20261122-tp-tls-h1 | 3 (0) | 500 | 568831 | 630271 | 648703 | 674815 | 630442 ± 734 | 1.33 | 55% |
| p0-synth-20261122-tp-tls-h2 | 3 (0) | 500 | 568319 | 629247 | 649215 | 676863 | 629930 ± 5141 | 1.52 | 50% |
| p0-synth-20261122-tp-uph2c | 3 (0) | 500 | 566783 | 627199 | 645631 | 669183 | 627028 ± 734 | 1.25 | 55% |

## Synthetic trace vs Poisson at the middle load
| point | runs (valid) | offered req/s | request_total merged p50 | p99 | p99.9 | max (µs) | per-run p99 mean ± 95% CI (µs) | SUT cores | gen CPU |
|---|---|---|---|---|---|---|---|---|---|
| p0-synth-20261122-trace-null | 1 (0) | 500 | 3788799 | 12722175 | 15646719 | 18939903 | 12722175 ± NaN | 1.31 | 51% |
| p0-synth-20261122-trace-poisson-null | 1 (0) | 500 | 568319 | 629247 | 646143 | 677887 | 629247 ± NaN | 1.32 | 51% |

## Ground-truth control (pass-through must leak everything, alter nothing)
- streams checked: 22229; injected spans: 4438; leaked: 4438; benign streams altered: 0; parse errors: 0; incomplete: 0

## Validity
- 0/53 runs flagged valid. Invalid reasons: {"['dispatch', 'lag', 'p99']": 53, "['generator', 'CPU', '67%']": 2, "['generator', 'CPU', '66%']": 3, "['generator', 'CPU', '62%']": 1}
