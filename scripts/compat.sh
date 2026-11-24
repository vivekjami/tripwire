#!/usr/bin/env bash
# Compatibility matrix (Phase 1 exit criterion): real clients against the gateway in front of twmock.
# Always runs: curl (stream + non-stream), the third-party Go client (compat/gosdk).
# Runs if present: the official OpenAI Python and TypeScript SDKs (scripts/compat/*.py|.mjs) when
# TW_PYTHON / TW_NODE point at interpreters that have the SDKs installed.
# Writes bench/compat/<date>/matrix.md. Ports are loopback only.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
D="$ROOT/bench/compat/$(date -u +%Y%m%d)"; mkdir -p "$D"
W="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$W"' EXIT
cd "$ROOT" && CGO_ENABLED=0 go build -o .bin/ ./cmd/tripwire ./cmd/twmock || exit 1
head -c 32 /dev/urandom | base64 >"$W/pepper"; echo "upstream-secret" >"$W/cred"
OUT="$(.bin/tripwire genkey -agent compat -pepper-file "$W/pepper")"
KEY="$(sed -n 's/^api key.*: //p' <<<"$OUT")"; HASH="$(sed -n 's/.*sha256: "\(.*\)".*/\1/p' <<<"$OUT")"
cat >"$W/c.yaml" <<YML
version: "0.9"
listen: {data: "127.0.0.1:18180", admin: "127.0.0.1:19190"}
upstreams: {mock: {url: "http://127.0.0.1:18100", credential_file: "$W/cred"}}
routes: [{model: "*", upstream: mock}]
auth: {pepper_file: "$W/pepper", api_keys: [{agent: compat, sha256: "$HASH"}]}
agents: [{id: compat, tenant: t, models: ["gpt-*"]}]
YML
.bin/twmock -listen 127.0.0.1:18100 -admin "" >"$W/mock.log" 2>&1 &
.bin/tripwire -config "$W/c.yaml" >"$W/gw.log" 2>&1 &
for _ in $(seq 1 50); do curl -fs localhost:19190/readyz >/dev/null 2>&1 && break; sleep 0.1; done
export TW_GATEWAY_URL=http://127.0.0.1:18180 TW_API_KEY="$KEY"
res() { printf '| %s | %s | %s |\n' "$1" "$2" "$3" | tee -a "$D/matrix.md"; }
{ echo "# Compatibility matrix (gateway -> twmock), $(date -u +%FT%TZ), commit $(git rev-parse --short HEAD)"; echo; echo "| client | case | result |"; echo "|---|---|---|"; } >"$D/matrix.md"

body='{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}'
code=$(curl -s -o "$W/o" -w '%{http_code}' -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d "$body" $TW_GATEWAY_URL/v1/chat/completions)
grep -q '"chat.completion"' "$W/o" && [ "$code" = 200 ] && res "curl $(curl --version | head -1 | cut -d' ' -f2)" "non-stream" "PASS" || res curl "non-stream" "FAIL ($code)"
curl -sN -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d '{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}' $TW_GATEWAY_URL/v1/chat/completions >"$W/s"
[ "$(grep -c '^data: {' "$W/s")" -ge 3 ] && tail -c 14 "$W/s" | grep -q '\[DONE\]' && res curl "stream (-N, incremental)" "PASS" || res curl "stream" "FAIL"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer nope' $TW_GATEWAY_URL/v1/models); [ "$code" = 401 ] && res curl "bad key -> 401" PASS || res curl "bad key" "FAIL ($code)"

if (cd compat/gosdk && go test -count=1 ./... >"$W/go.out" 2>&1); then
  for t in TestNonStream TestStream TestModelsList TestAuthFailureIsAnAPIError TestUnknownModelIs404; do res "go-openai (sashabaranov) $(cd compat/gosdk && go list -m -f '{{.Version}}' github.com/sashabaranov/go-openai)" "$t" PASS; done
else res "go-openai (sashabaranov)" "suite" "FAIL"; cat "$W/go.out"; fi

if [ -n "${TW_PYTHON:-}" ] && "$TW_PYTHON" -c 'import openai' 2>/dev/null; then
  ver=$("$TW_PYTHON" -c 'import openai;print(openai.__version__)')
  if "$TW_PYTHON" scripts/compat/py_sdk.py >"$W/py.out" 2>&1; then res "openai-python $ver" "non-stream, stream, models, errors" PASS; else res "openai-python $ver" "suite" "FAIL"; cat "$W/py.out"; fi
else res "openai-python" "-" "NOT RUN (no interpreter with the SDK; set TW_PYTHON)"; fi
if [ -n "${TW_NODE:-}" ] && [ -d "${TW_NODE_MODULES:-/nonexistent}/openai" ]; then
  if NODE_PATH="$TW_NODE_MODULES" "$TW_NODE" scripts/compat/ts_sdk.mjs >"$W/ts.out" 2>&1; then res "openai-node" "non-stream, stream, models, errors" PASS; else res "openai-node" "suite" "FAIL"; cat "$W/ts.out"; fi
else res "openai-node (TypeScript)" "-" "NOT RUN (no node + SDK; set TW_NODE and TW_NODE_MODULES)"; fi
cat "$D/matrix.md"
