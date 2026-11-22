#!/usr/bin/env bash
# Rig lifecycle: up | down | status
#
# Tripwire does not assume a cloud provider. Two modes:
#
#  1. BYO hosts (default). Put three reachable Linux hosts in deploy/rig/rig.env
#     (copy rig.env.example). `up` prepares them (host-setup.sh) and copies the
#     harness binaries; `down` stops our processes. Nothing is created, so
#     nothing can be orphaned or billed by this script.
#
#  2. Provider hook. Set RIG_PROVIDER=<name> and provide
#     deploy/rig/providers/<name>.sh implementing `up|down|status` (Terraform or
#     a provider CLI). It must print HOST_A/HOST_B/HOST_C to rig.env on `up`
#     and destroy EVERYTHING it created on `down`. `down` is run after every
#     benchmark session: the exit checklist requires proving no resources remain.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
cmd="${1:-}"

load_env() {
  [[ -f "$here/rig.env" ]] || { echo "rig.sh: $here/rig.env missing (copy rig.env.example)" >&2; exit 1; }
  # shellcheck disable=SC1091
  source "$here/rig.env"
  : "${HOST_A:?}" "${HOST_B:?}" "${HOST_C:?}" "${SSH_USER:=root}"
  SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new ${SSH_KEY:+-i "$SSH_KEY"})
}
sshx() { local h="$1"; shift; ssh "${SSH_OPTS[@]}" "$SSH_USER@$h" "$@"; }

provider() {
  local p="$here/providers/${RIG_PROVIDER}.sh"
  [[ -x "$p" ]] || { echo "rig.sh: provider hook $p not found or not executable" >&2; exit 1; }
  "$p" "$1"
}

case "$cmd" in
  up)
    [[ -n "${RIG_PROVIDER:-}" ]] && provider up
    # the "local" provider is a self-contained single-host synthetic rig: no ssh hosts
    [[ "${RIG_PROVIDER:-}" == local ]] && exit 0
    load_env
    mkdir -p "$root/.bin"
    ( cd "$root" && CGO_ENABLED=0 go build -trimpath -o .bin/ ./cmd/twmock ./cmd/twnull ./cmd/twload ./cmd/twfit )
    for pair in "A:$HOST_A" "B:$HOST_B" "C:$HOST_C"; do
      role="${pair%%:*}"; host="${pair#*:}"
      echo "== $role ($host)"
      sshx "$host" "mkdir -p /opt/tripwire/deploy"
      scp "${SSH_OPTS[@]}" -r "$here" "$root/deploy/sysctl" "$SSH_USER@$host:/opt/tripwire/deploy/" >/dev/null
      scp "${SSH_OPTS[@]}" "$root"/.bin/* "$SSH_USER@$host:/opt/tripwire/" >/dev/null
      sshx "$host" "bash /opt/tripwire/deploy/rig/host-setup.sh $role"
    done
    echo "rig up. Next: bench/RUNBOOK.md pre-flight (noise canary, twload timer, make selfcheck)."
    ;;
  down)
    if [[ "${RIG_PROVIDER:-}" == local ]]; then provider down; exit $?; fi
    if [[ -f "$here/rig.env" ]]; then
      load_env
      for h in "$HOST_A" "$HOST_B" "$HOST_C"; do
        sshx "$h" "pkill -x twmock; pkill -x twnull; pkill -x twload; pkill -x tripwire; pkill -x twclf; true" || true
      done
    else
      echo "rig.sh: no rig.env: no BYO hosts to clean"
    fi
    if [[ -n "${RIG_PROVIDER:-}" ]]; then provider down; fi
    echo "rig down. If a provider created resources, VERIFY in its console/CLI that none remain, and log cost in bench/COSTS.md."
    ;;
  status)
    load_env
    for pair in "A:$HOST_A" "B:$HOST_B" "C:$HOST_C"; do
      echo "== ${pair%%:*} ${pair#*:}"; sshx "${pair#*:}" "uptime; pgrep -a -x 'twmock|twnull|twload|tripwire|twclf' || echo '(no tripwire processes)'" || echo UNREACHABLE
    done
    [[ -n "${RIG_PROVIDER:-}" ]] && provider status
    ;;
  *) echo "usage: rig.sh up|down|status" >&2; exit 2 ;;
esac
