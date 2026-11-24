#!/usr/bin/env bash
# Provider hook "local": a SYNTHETIC single-host rig.
#
# Everything runs on this machine with the three roles pinned to disjoint core
# sets (generator / mock / gateway), loopback networking and a throw-away CA for
# the TLS runs. It exercises the whole rig lifecycle (up -> sessions -> down with
# an orphan check) and produces results with the right SHAPE, but a shared,
# usually virtualised host is not a measurement environment: runs are stamped
# shape-only by envinfo and must never be cited as published numbers.
#
#   providers/local.sh up|down|status
#
# Layout (override with RIG_LOCAL_* env):
#   cores: GEN=0-2  MOCK=3-4  GW=5-6   (of 8)  -> .rig-local/env
#   ports: mock 9300  null 9302 (admin 9303)  null-tls 9304 (admin 9305)
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
state="$root/.rig-local"
cmd="${1:-}"
PORTS=(9300 9302 9303 9304 9305 9306 9307 9308 9309 9310 9311)
PROCS=(twmock twnull twload)

listeners() { # prints "port pid" for rig ports still bound
  local p
  for p in "${PORTS[@]}"; do
    (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null && echo "$p"
  done
  return 0
}
leftovers() { for n in "${PROCS[@]}"; do pgrep -x "$n" || true; done; }

case "$cmd" in
  up)
    n="$(nproc)"
    if (( n < 7 )); then echo "local rig: needs >= 7 cores for disjoint pinning, have $n" >&2; exit 1; fi
    if [[ -n "$(leftovers)$(listeners)" ]]; then echo "local rig: leftovers from a previous session; run 'down' first" >&2; exit 1; fi
    mkdir -p "$state/tls" "$root/.bin"
    ( cd "$root" && CGO_ENABLED=0 go build -trimpath -o .bin/ ./cmd/twmock ./cmd/twnull ./cmd/twload ./cmd/twfit ./cmd/twagg ./cmd/twcanary ./cmd/twtrace )
    # throw-away CA + server cert for the TLS runs (never leaves this directory)
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
      -keyout "$state/tls/ca.key" -out "$state/tls/ca.pem" -subj "/CN=tripwire-local-rig-ca" >/dev/null 2>&1
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$state/tls/srv.key" \
      -out "$state/tls/srv.csr" -subj "/CN=localhost" >/dev/null 2>&1
    printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' >"$state/tls/ext.cnf"
    openssl x509 -req -in "$state/tls/srv.csr" -CA "$state/tls/ca.pem" -CAkey "$state/tls/ca.key" -CAcreateserial \
      -days 2 -out "$state/tls/srv.pem" -extfile "$state/tls/ext.cnf" >/dev/null 2>&1
    chmod 600 "$state"/tls/*.key
    cat >"$state/env" <<ENV
GEN_CORES=${RIG_LOCAL_GEN_CORES:-0-2}
MOCK_CORES=${RIG_LOCAL_MOCK_CORES:-3-4}
GW_CORES=${RIG_LOCAL_GW_CORES:-5-6}
ENV
    echo "local rig up: $(cat "$state/env" | tr '\n' ' ')"
    ;;
  down)
    # 1. stop everything we may have started (session scripts register pids too)
    if [[ -d "$state/pids" ]]; then
      for f in "$state"/pids/*; do [[ -f "$f" ]] && kill "$(cat "$f")" 2>/dev/null || true; done
    fi
    for n in "${PROCS[@]}"; do pkill -x "$n" 2>/dev/null || true; done
    sleep 1
    for n in "${PROCS[@]}"; do pkill -9 -x "$n" 2>/dev/null || true; done
    sleep 0.3
    # 2. remove state (keys included)
    rm -rf "$state"
    # 3. VERIFY: no processes, no bound rig ports, no state dir
    bad="$(leftovers)"; lp="$(listeners)"
    if [[ -n "$bad" || -n "$lp" || -e "$state" ]]; then
      echo "local rig DOWN FAILED: processes=[$bad] ports=[$lp] state_dir_exists=$([[ -e $state ]] && echo yes || echo no)" >&2
      exit 1
    fi
    echo "local rig down: verified no tripwire processes, no listeners on ${PORTS[*]}, no state directory"
    ;;
  status)
    echo "state dir: $([[ -d $state ]] && echo present || echo absent)"
    echo "processes: $(leftovers | tr '\n' ' ')"
    echo "listeners: $(listeners | tr '\n' ' ')"
    ;;
  *) echo "usage: local.sh up|down|status" >&2; exit 2 ;;
esac
