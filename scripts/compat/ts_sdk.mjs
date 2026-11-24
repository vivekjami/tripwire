// Official OpenAI Node/TypeScript SDK against the gateway. Env: TW_GATEWAY_URL, TW_API_KEY.
import OpenAI from "openai";
import assert from "node:assert/strict";

const baseURL = process.env.TW_GATEWAY_URL.replace(/\/$/, "") + "/v1";
const c = new OpenAI({ baseURL, apiKey: process.env.TW_API_KEY, maxRetries: 0, timeout: 20000 });

const r = await c.chat.completions.create({ model: "gpt-4o", messages: [{ role: "user", content: "hello" }] });
assert.equal(r.choices[0].message.role, "assistant");
assert.ok(r.choices[0].message.content);

let n = 0, text = "";
for await (const chunk of await c.chat.completions.create({ model: "gpt-4o", stream: true, messages: [{ role: "user", content: "hello" }] })) {
  n++; text += chunk.choices?.[0]?.delta?.content ?? "";
}
assert.ok(n >= 3 && text.length > 0);

for await (const m of c.models.list()) assert.ok(m.id.startsWith("gpt-"), `model ${m.id} outside scope`);

await assert.rejects(new OpenAI({ baseURL, apiKey: "tw_bad_" + "a".repeat(43), maxRetries: 0 }).chat.completions.create({ model: "gpt-4o", messages: [{ role: "user", content: "x" }] }), (e) => e.status === 401);
await assert.rejects(c.chat.completions.create({ model: "claude-secret", messages: [{ role: "user", content: "x" }] }), (e) => e.status === 404);
console.log("ok");
