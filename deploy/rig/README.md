# Benchmark rig

Three Linux VMs (A load+mocks, B gateway+classifier, C storage+observability), rented **by the hour for runs only**. Procedure: [bench/RUNBOOK.md](../../bench/RUNBOOK.md). Cost log: [bench/COSTS.md](../../bench/COSTS.md).

| Role | Runs | Sizing guidance (ARCHITECTURE §3.2) |
|---|---|---|
| A | `twload`, `twmock` | 16 vCPU; generator and mock on disjoint core sets |
| B | gateway (`twnull` in Phase 0), `twclf` | 16 vCPU; gateway cores 0-11, classifier 12-15 |
| C | ClickHouse, Prometheus, Grafana, Tempo | 8-16 vCPU, NVMe |

## Use
```bash
cp deploy/rig/rig.env.example deploy/rig/rig.env   # three reachable hosts (gitignored)
make rig-up        # builds binaries, ships them, applies sysctl/governor/THP/limits on each host
make rig-status
# ... bench/RUNBOOK.md ...
make rig-down      # ALWAYS; then verify no resources remain and log the session in bench/COSTS.md
```

## Providers
No cloud provider is assumed. Two modes (see the header of `rig.sh`): **bring-your-own hosts** (default; nothing is created or billed by Tripwire's scripts) or a provider hook `deploy/rig/providers/<name>.sh up|down|status` (Terraform or a provider CLI) selected with `RIG_PROVIDER=<name>`. **No provider hook is shipped yet**; choosing one is an open decision (docs/phases/P0.md).

`host-setup.sh` is untested against real VMs (none were available while authoring); expect to fix small things on the first session and record them as amendments.
