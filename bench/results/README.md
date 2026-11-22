# bench/results

One directory per run: `<run-id>/{env.json, summary.json, raw/*.hdr, raw/config.json[, raw/errors.csv]}`.
Result directories are **immutable once published**; a rerun gets a new run id.

- `env.json`: host, kernel, CPU, governor, sysctls, Go version, git SHA/dirty flag. Contains no hostname; home paths are scrubbed.
- `summary.json`: percentiles in **microseconds**, rates, generator health, ground-truth verdict, and `valid` plus `invalid_reasons`. A run with `valid=false` must not be cited.
- `raw/*.hdr`: HdrHistogram V2 compressed (1 µs resolution, 3 significant digits). Merge histograms across runs; never average percentiles.

Runs whose `env.json` says `WSL2 (shape-only ...)` are development runs: they validate the harness and the shape of the curves, and are **not publishable numbers**.

`p0-local-*` are the Phase 0 single-host shape runs (see `docs/phases/P0.md`).
