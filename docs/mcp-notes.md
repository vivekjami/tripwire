# MCP notes (pre-work for Phase 2 WP2.7)

> **STATUS: UNVERIFIED.** IMPLEMENTATION_PLAN Day 1 calls for re-reading the current MCP
> spec and changelog and recording exact revision strings and header requirements here.
> That re-read **has not been done**: the authoring session had no web access. Everything
> below is copied from ARCHITECTURE §0/§4.4 (written November 2026) and is what `twmock`
> and `twload` currently implement. **Before Phase 2, re-read the live spec and replace
> this banner with the verification date and diffs.**

## Revisions targeted (strings as in ARCHITECTURE §0)
| Revision | Shape | Implemented in twmock / twload |
|---|---|---|
| `2026-07-28` | Stateless: no protocol sessions, no `Mcp-Session-Id`, no `initialize`, no SSE resumability, no GET stream; **`Mcp-Method` / `Mcp-Name` required on Streamable-HTTP POSTs and must mirror the body** | header/body equality enforced by the mock (HTTP 400, code −32001); `twload --mcp-mismatch-frac` sends contradicting `Mcp-Name` to test that a *gateway* rejects too |
| `2025-11-25` | `initialize` → `Mcp-Session-Id`; resumability via `Last-Event-ID` | session table in the mock; `twload` does one `initialize` per run; resumption **not** modelled yet (Phase 2, F-24) |
| `2024-11-05` | HTTP+SSE, deprecated | not supported (non-goal) |

Version selection: `MCP-Protocol-Version` request header; the mock defaults to `2025-11-25` when absent (`--mcp-default-version`).

## Header/body equality rules assumed
- `Mcp-Method` must equal the JSON-RPC `method` exactly.
- `Mcp-Name` must equal `params.name` (`tools/call`, `prompts/get`) or `params.uri` (`resources/read`).
- Mismatch ⇒ reject; the gateway must verify and then act on the **body** (headers are a routing hint only; mismatch is a smuggling vector, T1/F-25).

## Methods the mock serves
`initialize` (legacy), `tools/list`, `tools/call`, `resources/read`, `prompts/get`. Notifications (no `id`) get `202`. A `tools/call` can answer as JSON or as `text/event-stream` (a progress notification, then the final response event) when the request spec sets `sse`.

## Hostile mode (`twmock --hostile`)
Tool results and prompts carry an instruction aimed at the model plus an `attacker@example.org` exfil target; `get_customer`'s description mutates after `--hostile-after` `tools/list` calls (rug pull, T8/F-26).

## To verify before Phase 2 (checklist)
- [ ] Latest spec revision string(s) and their changelog; has `2026-07-28` shipped as described?
- [ ] Exact required header names/casing on Streamable-HTTP requests; `x-mcp-header` custom mirrored-parameter headers.
- [ ] Whether JSON-RPC batching exists in each revision.
- [ ] SSE event shape for streamed `tools/call` results; terminal-event rules.
- [ ] `_meta` trace-context propagation keys.
- [ ] Authorization model (resource indicators / audience binding) as it affects credential brokering (ARCHITECTURE §8.3).
