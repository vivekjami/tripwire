#!/usr/bin/env bash
# Prepare ONE benchmark VM. Run as root on each of A, B, C. Idempotent.
#   host-setup.sh <role: A|B|C>
# Applies the sysctl profile, performance governor, THP off, fd limits, and
# verifies clock sync. Does not install the Go toolchain: binaries are built
# off-box and copied (rig.sh up), so the rig carries no compiler noise.
set -euo pipefail
role="${1:?role A|B|C}"
here="$(cd "$(dirname "$0")" && pwd)"

echo "[$role] sysctl"
install -m 0644 "$here/../sysctl/99-tripwire.conf" /etc/sysctl.d/99-tripwire.conf
sysctl --system >/dev/null

echo "[$role] CPU governor -> performance"
if compgen -G "/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor" >/dev/null; then
  for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance >"$g" || true; done
else
  echo "[$role] WARNING: no cpufreq (virtualised guest?) - governor not controllable; record this in COSTS/notes"
fi

echo "[$role] transparent hugepages -> never"
[[ -w /sys/kernel/mm/transparent_hugepage/enabled ]] && echo never >/sys/kernel/mm/transparent_hugepage/enabled || true

echo "[$role] fd limits"
cat >/etc/security/limits.d/99-tripwire.conf <<LIM
*  soft  nofile  1048576
*  hard  nofile  1048576
LIM

echo "[$role] clock sync (rig requires chrony offset < 100us for the emit/receive join)"
if command -v chronyc >/dev/null; then
  chronyc tracking | sed -n '1,/^Last offset/p' | tail -3
else
  echo "[$role] WARNING: chronyc not installed; install chrony (cross-VM timing is NOT used for published latency, but trace stamps are)"
fi

case "$role" in
  A) cat >/etc/tripwire-cpus.env <<ENV
# VM A: load generator and mocks on DISJOINT cores so the mock never starves the generator
TW_LOAD_CPUS=0-7
TW_MOCK_CPUS=8-15
ENV
  ;;
  B) cat >/etc/tripwire-cpus.env <<ENV
# VM B: gateway on 0-11, classifier sidecar isolated on 12-15 (ARCHITECTURE §3.2)
TW_GW_CPUS=0-11
TW_CLF_CPUS=12-15
ENV
  ;;
  C) : >/etc/tripwire-cpus.env ;;
  *) echo "unknown role $role" >&2; exit 2 ;;
esac
echo "[$role] done. Re-run 'twload timer' here to choose --spin-margin; then bench/RUNBOOK.md pre-flight."
