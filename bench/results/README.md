# bench/results

One directory per run: `<run-id>/{env.json, summary.json, raw/*.hdr, raw/config.json[, raw/errors.csv]}`.
Result directories are **immutable once published**; a rerun gets a new run id.

- `env.json`: host, kernel, CPU, governor, sysctls, Go version, git SHA/dirty flag. Contains no hostname; home paths are scrubbed.
- `summary.json`: percentiles in **microseconds**, rates, generator health, ground-truth verdict, and `valid` plus `invalid_reasons`. A run with `valid=false` must not be cited.
- `raw/*.hdr`: HdrHistogram V2 compressed (1 µs resolution, 3 significant digits). Merge histograms across runs; never average percentiles.

Runs whose `env.json` says `WSL2 (shape-only ...)` are development runs: they validate the harness and the shape of the curves, and are **not publishable numbers**.

`p0-local-*` are the Phase 0 single-host shape runs (see `docs/phases/P0.md`).

`p0-synth-20261122-*` are the 53 runs of the Phase 0 **synthetic local rig** session (`make rig-local`; log, pre-flight output and `analysis.md` in `bench/sessions/p0-synth-20261122/`). All are `valid=false` (dispatch-lag p99 > 200 µs on this virtualised host; three direct runs at 1000 req/s also exceeded 60 % generator CPU) and shape-only. Their `env.json` records the parent commit with `git_dirty=true`, because the session's own tooling was committed together with the results.

`p1-synth-20261124*` are the Phase 1 parse-only performance sessions (gateway vs null proxy; `bench/sessions/p1-synth-*/analysis.md`): `p1-synth-20261124` (coarse knee sweep + comparison, before optimisation), `-opt1`/`-opt2` (comparison after each optimisation) and `-fine` (25 req/s knee sweep). `p1-lineage-null-1M` is the lineage pipeline into a null sink. All shape-only; none is `valid`.
