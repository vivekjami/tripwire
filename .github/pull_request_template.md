## What and why

<!-- One paragraph. Link the phase / work package (e.g. P1 / WP1.4) and any ADR touched. -->

## Self-review checklist (docs/CONVENTIONS.md)

- [ ] **Limits**: every new input has a size/depth/count/time bound
- [ ] **Deadlines**: every blocking call has a context or deadline; no goroutine can outlive its request
- [ ] **Allocations**: hot-path changes carry a benchmark and `-benchmem`; escape-check unchanged (`make escape-check`)
- [ ] **Fuzz**: a new or changed parser/decoder has its `Fuzz*` target in this PR
- [ ] **Metrics**: new behaviour is observable (metric/log field on the allow-list); no payload or value in any log
- [ ] **Tests**: `make test` passes with `-race`; failure paths are tested, not just the happy path
- [ ] **Docs/ADR**: a deviation from ARCHITECTURE.md is recorded in `docs/adr/AMENDMENTS.md` in this PR
- [ ] **Numbers**: no performance/accuracy figure is typed by hand anywhere; they come from `bench/results/` or `eval/results/`

## Evidence

<!-- Test output, benchstat, or a bench/results run id. "It works on my machine" is not evidence. -->
