# OpenAI wire-format notes (pre-work for Phase 1/2)

> **STATUS: UNVERIFIED against current docs** (no web access in the authoring session; see
> `docs/mcp-notes.md`). Sourced from ARCHITECTURE §0/§4.2-4.3 and what `twmock` emits.
> Re-verify against the live API reference before Phase 1's SDK compatibility matrix.

## Chat Completions (`POST /v1/chat/completions`)
- Stream: SSE, each event `data: {chunk}\n\n`, chunk object `chat.completion.chunk`; first chunk `delta:{role:"assistant",content:""}`; content chunks `delta:{content:<fragment>}`; final chunk `delta:{}` with `finish_reason`; terminated by `data: [DONE]`.
- Non-stream: one `chat.completion` with `choices[].message.content`.
- `metadata` values are strings (so the mock's control field `metadata.tw_mock` is a JSON-in-string).
- JSON string fragments may be raw UTF-8 or `\uXXXX`-escaped; **astral characters may arrive as a split surrogate pair across events**. `twmock --chunk adversarial` produces exactly that; `groundtruth.DecodeJSONString` keeps lone surrogates so the client can rejoin them.

## Responses API (`POST /v1/responses`), subset
Typed events with `event:` lines and `sequence_number`: `response.created`, `response.output_text.delta` (fields `item_id`, `output_index`, `content_index`, `delta`, and a random `obfuscation` padding field that **must be preserved untouched**), `response.output_text.done`, `response.completed` (carries the full final text, so it is re-inspected as the authoritative copy). There is **no `[DONE]` sentinel**; termination is `response.completed`/failure. WebSocket mode is a non-goal (rejected at the edge).

## Hosted MCP in Responses
`tools[].type == "mcp"` makes the *provider* call the MCP server directly: an egress bypass the gateway must detect (Phase 2, F-27). Not modelled in Phase 0.

## What `twmock` does NOT model yet
`logprobs`, `usage` chunks, tool-call deltas (`delta.tool_calls[].function.arguments` fragments: needed for ARCHITECTURE §5.5, Phase 2 WP2.5), refusal deltas, reasoning events. These are added when the gateway features that consume them land.
