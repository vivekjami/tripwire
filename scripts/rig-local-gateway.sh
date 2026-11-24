#!/usr/bin/env bash
# Phase 1 parse-only performance session on the SYNTHETIC local rig.
#   floor    : twload -> twnull -> twmock        (pass-through, no parsing)
#   gateway  : twload -> tripwire -> twmock      (auth, strict parse, SSE decode, scan, lineage events; NO detectors)
# 1. knee sweep  : find the null proxy's knee (highest rate that stays healthy)
# 2. comparison  : direct / null / gateway at 70% of knee and at the knee, 5 runs each, randomized
# Shape-only on this host (see docs/phases/P0.md); the plan's criteria are evaluated against the
# numbers anyway so the procedure is proven, and re-run on a real rig later.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
S="${1:-p1-synth-$(date -u +%Y%m%d)}"
OUT="$ROOT/bench/results"; LOG="$ROOT/bench/sessions/$S"; mkdir -p "$LOG" "$OUT"
DUR="${DUR:-15s}"; WARM="${WARM:-3s}"; GAP="${GAP:-const:5ms}"; EV="${EV:-64}"
SWEEP=(${SWEEP:-100 200 300 400 500 600}); SWEEP_RUNS="${SWEEP_RUNS:-3}"; RUNS="${RUNS:-5}"
BIN="$ROOT/.bin"; ST="$ROOT/.rig-local"; WORK="$ST/work"
"$ROOT/deploy/rig/providers/local.sh" up | tee "$LOG/rig-up.txt"
trap '"$ROOT/deploy/rig/providers/local.sh" down | tee "$LOG/rig-down.txt"' EXIT
source "$ST/env"; mkdir -p "$WORK" "$ST/pids"
( cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o .bin/ ./cmd/tripwire ./cmd/twmock ./cmd/twnull ./cmd/twload ./cmd/twagg )
reg() { echo "$1" >"$ST/pids/$2"; }
wait_port() { for _ in $(seq 1 100); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.1; done; echo "port $1 never opened" >&2; return 1; }

head -c 32 /dev/urandom | base64 >"$WORK/pepper"; echo upstream-cred >"$WORK/cred"
KOUT="$("$BIN/tripwire" genkey -agent perf -pepper-file "$WORK/pepper")"
sed -n 's/^api key.*: //p' <<<"$KOUT" >"$WORK/key"; chmod 600 "$WORK/key" "$WORK/pepper"
HASH="$(sed -n 's/.*sha256: "\(.*\)".*/\1/p' <<<"$KOUT")"
cat >"$WORK/gw.yaml" <<YML
version: "0.9"
listen: {data: "127.0.0.1:9310", admin: "127.0.0.1:9311"}
runtime: {gomaxprocs: 2}
upstreams: {mock: {url: "http://127.0.0.1:9300", credential_file: "$WORK/cred"}}
routes: [{model: "*", upstream: mock}]
auth: {pepper_file: "$WORK/pepper", api_keys: [{agent: perf, sha256: "$HASH"}]}
agents: [{id: perf, tenant: perf, models: ["*"]}]
YML
start_mock() { # fresh process and logs per run, as in the Phase 0 session
  [[ -f "$ST/pids/mock" ]] && { kill "$(cat "$ST/pids/mock")" 2>/dev/null || true; while kill -0 "$(cat "$ST/pids/mock")" 2>/dev/null; do sleep 0.05; done; }
  rm -f "$WORK/gt.jsonl" "$WORK/emit.csv"
  taskset -c "$MOCK_CORES" "$BIN/twmock" -listen 127.0.0.1:9300 -admin "" -h2c -ground-truth "$WORK/gt.jsonl" -emit-log "$WORK/emit.csv" -emit-sample 0.05 >>"$LOG/twmock.log" 2>&1 & reg $! mock
  wait_port 9300
}
start_mock
taskset -c "$GW_CORES" "$BIN/twnull" -listen 127.0.0.1:9302 -admin 127.0.0.1:9303 -upstream http://127.0.0.1:9300 -gomaxprocs 2 >"$LOG/twnull.log" 2>&1 & reg $! null; wait_port 9302
taskset -c "$GW_CORES" "$BIN/tripwire" -config "$WORK/gw.yaml" >"$LOG/tripwire.log" 2>&1 & reg $! gw; wait_port 9310

FIXED=(-duration "$DUR" -warmup "$WARM" -gap "$GAP" -events "$EV" -inject PCI.PAN:1 -inject-frac 0.2 -bearer-file "$WORK/key"
       -ground-truth "$WORK/gt.jsonl" -emit-log "$WORK/emit.csv" -emit-sample 0.05 -check-sample 0.05
       -mock-stats http://127.0.0.1:9300/_tw/stats -out "$OUT")
run() { # id target rate [extra...]
  local id="$1" target="$2" rate="$3"; shift 3
  echo "-- $id"
  taskset -c "$GEN_CORES" "$BIN/twload" run -target "$target" -rate "$rate" -run-id "$id" "${FIXED[@]}" "$@" >"$LOG/$id.txt" 2>&1 \
    || { rc=$?; [[ $rc == 3 || $rc == 4 ]] || { cat "$LOG/$id.txt"; return $rc; }; }
  start_mock
}
go_run() { # kind rate id
  case "$1" in
    direct) run "$3" http://127.0.0.1:9300 "$2" ;;
    null)   run "$3" http://127.0.0.1:9302 "$2" -sut-metrics http://127.0.0.1:9303/metrics ;;
    gw)     run "$3" http://127.0.0.1:9310 "$2" -sut-metrics http://127.0.0.1:9311/metrics ;;
  esac
}

echo "== knee sweep =="
if [[ -n "${SKIP_SWEEP:-}" ]]; then SWEEP=(); fi
plan=(); for L in "${SWEEP[@]}"; do for r in $(seq 1 "$SWEEP_RUNS"); do plan+=("null $L $r" "gw $L $r"); done; done
mapfile -t plan < <(printf '%s\n' "${plan[@]}" | shuf --random-source=<(yes 11))
for item in "${plan[@]}"; do read -r k L r <<<"$item"; go_run "$k" "$L" "$S-sweep-$k-L$L-r$r"; done

if [[ -n "${SKIP_CMP:-}" ]]; then echo "session $S sweep complete (comparison skipped)"; exit 0; fi
KNEE="${KNEE:-}"
if [[ -z "$KNEE" ]]; then KNEE="$("$BIN/twagg" -knee "$OUT"/$S-sweep-null-L* 2>/dev/null | tail -1 || true)"; fi
echo "null-proxy knee: ${KNEE:-unknown}"
echo "${KNEE:-}" >"$LOG/knee.txt"
[[ -n "${KNEE:-}" ]] || { echo "could not determine a knee; set KNEE=<req/s> and rerun the comparison" >&2; exit 2; }
L70=$(( KNEE * 70 / 100 ))
echo "== comparison at 70% ($L70) and 100% ($KNEE) of the knee =="
plan=(); for L in "$L70" "$KNEE"; do for r in $(seq 1 "$RUNS"); do plan+=("direct $L $r" "null $L $r" "gw $L $r"); done; done
mapfile -t plan < <(printf '%s\n' "${plan[@]}" | shuf --random-source=<(yes 13))
for item in "${plan[@]}"; do read -r k L r <<<"$item"; go_run "$k" "$L" "$S-cmp-$k-L$L-r$r"; done
echo "session $S complete"
