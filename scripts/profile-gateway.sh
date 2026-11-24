#!/usr/bin/env bash
# CPU-profile the gateway (or, with MODE=null, the null proxy) under streaming load on the local synthetic rig (shape only).
#   [MODE=null] scripts/profile-gateway.sh [rate=250] [seconds=25]  -> /tmp/gw-cpu.pprof (or /tmp/null-cpu.pprof), prints the top frames
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; RATE="${1:-250}"; SECS="${2:-25}"
BIN="$ROOT/.bin"; W="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$W"' EXIT
( cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o .bin/ ./cmd/tripwire ./cmd/twmock ./cmd/twload )
head -c 32 /dev/urandom | base64 >"$W/pepper"; echo c >"$W/cred"
K="$("$BIN/tripwire" genkey -agent perf -pepper-file "$W/pepper")"
sed -n 's/^api key.*: //p' <<<"$K" >"$W/key"; H="$(sed -n 's/.*sha256: "\(.*\)".*/\1/p' <<<"$K")"
cat >"$W/c.yaml" <<YML
version: "0.9"
listen: {data: "127.0.0.1:19310", admin: "127.0.0.1:19311"}
runtime: {gomaxprocs: 2}
upstreams: {mock: {url: "http://127.0.0.1:19300", credential_file: "$W/cred"}}
routes: [{model: "*", upstream: mock}]
auth: {pepper_file: "$W/pepper", api_keys: [{agent: perf, sha256: "$H"}]}
agents: [{id: perf, tenant: perf, models: ["*"]}]
YML
taskset -c 3-4 "$BIN/twmock" -listen 127.0.0.1:19300 -admin "" >/dev/null 2>&1 &
if [[ "${MODE:-gw}" == null ]]; then
  ( cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o .bin/ ./cmd/twnull )
  taskset -c 5-6 "$BIN/twnull" -listen 127.0.0.1:19310 -admin 127.0.0.1:19311 -upstream http://127.0.0.1:19300 -gomaxprocs 2 >/dev/null 2>&1 &
  PROF=/tmp/null-cpu.pprof; SUT="$BIN/twnull"
else
  taskset -c 5-6 "$BIN/tripwire" -config "$W/c.yaml" >/dev/null 2>&1 &
  PROF=/tmp/gw-cpu.pprof; SUT="$BIN/tripwire"
fi
sleep 1
( sleep 6; curl -s "http://127.0.0.1:19311/debug/pprof/profile?seconds=$((SECS-10))" -o "$PROF" ) &
taskset -c 0-2 "$BIN/twload" run -target http://127.0.0.1:19310 -bearer-file "$W/key" -rate "$RATE" -duration "${SECS}s" -warmup 3s -events 64 -gap const:5ms -out "$W/res" -run-id prof >/dev/null 2>&1 || true
wait %3 2>/dev/null || true; sleep 1
go tool pprof -top -nodecount 35 "$SUT" "$PROF" 2>/dev/null | head -48
