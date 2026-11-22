# Rig cost log

Record every rig session here as you go; do not estimate from memory (IMPLEMENTATION_PLAN §1.4).

| Date (UTC) | Session purpose | Provider / instance types | Hours up | Cost | `rig-down` verified (resources remaining = 0) |
|---|---|---|---|---|---|
| 2026-11-22 | Phase 0 synthetic local rig session `p0-synth-20261122` (53 runs + pre-flight) | `local` provider (this WSL2 laptop, 8 vCPU) | ≈ 0.75 | $0 | yes: `local.sh down` checks no processes, no listeners, no state dir |

Phase 0 rig sessions to date: **one synthetic local session ($0)**. No real cloud rig has been used (no provider chosen; see `docs/phases/P0.md`).
