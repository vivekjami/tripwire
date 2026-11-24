package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const good = `
version: "0.9"
listen: {data: ":8080", admin: "127.0.0.1:9090"}
upstreams:
  openai: {url: "https://api.openai.com", credential_file: /run/secrets/openai}
agents:
  - id: billing-bot
    tenant: acme
    models: ["gpt-4*"]
    limits: {rps: 50, burst: 100, concurrent_streams: 10}
auth:
  pepper_file: /run/secrets/pepper
  api_keys:
    - agent: billing-bot
      sha256: "0000000000000000000000000000000000000000000000000000000000000000"
`

func TestParseGoodAndDefaults(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if c.Limits.HeaderBytes != 32<<10 || c.Limits.BodyBytes != 8<<20 || c.Limits.GlobalInflight != 60000 {
		t.Fatalf("defaults not applied: %+v", c.Limits)
	}
	if c.Agents[0].Limits.ConcurrentStreams != 10 {
		t.Fatalf("agent: %+v", c.Agents[0])
	}
}

func TestEmptyFileIsDefaults(t *testing.T) {
	// Defaults alone have no version problem and no required-but-missing fields.
	if _, err := Parse([]byte("")); err != nil {
		t.Fatalf("empty config must equal defaults: %v", err)
	}
}

func TestUnknownFieldRejectedWithLine(t *testing.T) {
	_, err := Parse([]byte("version: \"0.9\"\nlisten:\n  data: \":1\"\n  admn: \":2\"\n"))
	if err == nil || !strings.Contains(err.Error(), "line 4") || !strings.Contains(err.Error(), "admn") {
		t.Fatalf("want line-4 unknown-field error, got %v", err)
	}
}

func TestValidationErrorsCarryLines(t *testing.T) {
	src := `version: "0.9"
listen:
  data: ":8080"
  admin: ":8080"
limits:
  body_bytes: -5
agents:
  - id: Bad_ID
    tenant: ""
  - id: ok
    tenant: t
    limits: {rps: 10}
auth:
  api_keys:
    - agent: ghost
      sha256: zz
`
	_, err := Parse([]byte(src))
	es, ok := err.(Errors)
	if !ok {
		t.Fatalf("want Errors, got %T %v", err, err)
	}
	want := map[string]int{
		"listen.admin":            4,
		"limits.body_bytes":       6,
		"agents[0].id":            8,
		"agents[0].tenant":        9,
		"agents[1].limits.burst":  12,
		"auth.api_keys[0].agent":  15,
		"auth.api_keys[0].sha256": 16,
		"auth.pepper_file":        13,
	}
	got := map[string]int{}
	for _, e := range es {
		got[e.Path] = e.Line
	}
	for p, line := range want {
		if got[p] != line {
			t.Errorf("%s: line %d, want %d (all: %v)", p, got[p], line, es)
		}
	}
}

func TestVersionMismatch(t *testing.T) {
	if _, err := Parse([]byte(`version: "9.9"`)); err == nil || !strings.Contains(err.Error(), "unsupported schema version") {
		t.Fatalf("got %v", err)
	}
}

func TestParseBytes(t *testing.T) {
	for in, want := range map[string]int64{"1024": 1024, "1KiB": 1024, "6GiB": 6 << 30, "512MiB": 512 << 20} {
		if got, err := ParseBytes(in); err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"", "-1", "abc", "1.5GiB", "0"} {
		if _, err := ParseBytes(in); err == nil {
			t.Errorf("%q should fail", in)
		}
	}
}

func TestSchemaMatchesStructAndIsValidJSON(t *testing.T) {
	b, err := Schema()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, must := range []string{`"additionalProperties": false`, `"global_inflight"`, `"concurrent_streams"`, `"credential_file"`, `"not_after"`} {
		if !strings.Contains(s, must) {
			t.Errorf("schema missing %s", must)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(good))
	f.Add([]byte("listen: [1,2"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Parse(b) }) // must never panic
}

// docs/config.schema.json is generated (make schema); it must not drift.
func TestCommittedSchemaIsCurrent(t *testing.T) {
	want, err := Schema()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../../docs/config.schema.json")
	if err != nil {
		t.Fatalf("docs/config.schema.json missing: run `make schema`: %v", err)
	}
	if strings.TrimSpace(string(got)) != strings.TrimSpace(string(want)) {
		t.Fatal("docs/config.schema.json is stale: run `make schema`")
	}
}

func TestExampleConfigParses(t *testing.T) {
	if _, err := LoadFile("../../deploy/config/tripwire.example.yaml"); err != nil {
		t.Fatal(err)
	}
}
