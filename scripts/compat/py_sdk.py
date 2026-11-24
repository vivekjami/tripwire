"""Official OpenAI Python SDK against the gateway. Env: TW_GATEWAY_URL, TW_API_KEY.
Exit status 0 only if every case passes. (Written for openai>=1.x.)"""
import os, sys
import openai
from openai import OpenAI

base, key = os.environ["TW_GATEWAY_URL"].rstrip("/") + "/v1", os.environ["TW_API_KEY"]
c = OpenAI(base_url=base, api_key=key, max_retries=0, timeout=20)

r = c.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "hello"}])
assert r.choices[0].message.role == "assistant" and r.choices[0].message.content, r

n, text = 0, ""
for chunk in c.chat.completions.create(model="gpt-4o", stream=True, messages=[{"role": "user", "content": "hello"}]):
    n += 1
    if chunk.choices:
        text += chunk.choices[0].delta.content or ""
assert n >= 3 and text, (n, text)

for m in c.models.list():
    assert m.id.startswith("gpt-"), f"model {m.id} outside the agent's scope was listed"

try:
    OpenAI(base_url=base, api_key="tw_bad_" + "a" * 43, max_retries=0).chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "x"}])
    sys.exit("bad key was accepted")
except openai.AuthenticationError:
    pass
try:
    c.chat.completions.create(model="claude-secret", messages=[{"role": "user", "content": "x"}])
    sys.exit("unknown model was accepted")
except openai.NotFoundError:
    pass
print("ok")
