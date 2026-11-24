# Compatibility matrix (gateway -> twmock), 2026-11-24T06:20:05Z, commit c4dcce3

| client | case | result |
|---|---|---|
| curl 8.14.1 | non-stream | PASS |
| curl | stream (-N, incremental) | PASS |
| curl | bad key -> 401 | PASS |
| go-openai (sashabaranov) v1.44.0 | TestNonStream | PASS |
| go-openai (sashabaranov) v1.44.0 | TestStream | PASS |
| go-openai (sashabaranov) v1.44.0 | TestModelsList | PASS |
| go-openai (sashabaranov) v1.44.0 | TestAuthFailureIsAnAPIError | PASS |
| go-openai (sashabaranov) v1.44.0 | TestUnknownModelIs404 | PASS |
| openai-python 3.58.0 | non-stream, stream, models, errors | PASS |
| openai-node (TypeScript) | - | NOT RUN (no node + SDK; set TW_NODE and TW_NODE_MODULES) |
