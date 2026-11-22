package load

import (
	"testing"

	"github.com/vivekjami/tripwire/internal/groundtruth"
)

func TestExtractEventChat(t *testing.T) {
	u, ok, err := extractEvent("chat", []byte(`{"choices":[{"index":0,"delta":{"content":"hi \ud83d"}}]}`))
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	u2, _, _ := extractEvent("chat", []byte(`{"choices":[{"delta":{"content":"\ude00!"}}]}`))
	if got := groundtruth.UnitsToString(append(u, u2...)); got != "hi 😀!" {
		t.Fatalf("got %q", got)
	}
	for _, p := range []string{`[DONE]`, `{"choices":[{"delta":{"role":"assistant"}}]}`, `{"choices":[{"delta":{},"finish_reason":"stop"}]}`, `{"choices":[]}`, `{"choices":[{"delta":{"content":null}}]}`} {
		if _, ok, err := extractEvent("chat", []byte(p)); ok || err != nil {
			t.Errorf("%s: ok=%v err=%v, want no content", p, ok, err)
		}
	}
	if _, _, err := extractEvent("chat", []byte(`{bad`)); err == nil {
		t.Error("expected parse error")
	}
}

func TestExtractEventResponses(t *testing.T) {
	u, ok, err := extractEvent("responses", []byte(`{"type":"response.output_text.delta","delta":"abc","sequence_number":3}`))
	if err != nil || !ok || groundtruth.UnitsToString(u) != "abc" {
		t.Fatalf("got %q ok=%v err=%v", groundtruth.UnitsToString(u), ok, err)
	}
	if _, ok, _ := extractEvent("responses", []byte(`{"type":"response.created"}`)); ok {
		t.Error("non-delta event produced content")
	}
	if _, ok, _ := extractEvent("responses", []byte(`{"type":"response.output_text.done","text":"full"}`)); ok {
		t.Error("done event must not be double-counted as a delta")
	}
}

func TestExtractNonStream(t *testing.T) {
	if s, err := extractNonStream("chat", []byte(`{"choices":[{"message":{"content":"x y"}}]}`)); err != nil || s != "x y" {
		t.Fatalf("%q %v", s, err)
	}
	if s, err := extractNonStream("responses", []byte(`{"output":[{"content":[{"text":"z"}]}]}`)); err != nil || s != "z" {
		t.Fatalf("%q %v", s, err)
	}
	if _, err := extractNonStream("chat", []byte(`{"choices":[]}`)); err == nil {
		t.Fatal("expected error")
	}
}

func TestUnitDeterministicAndUniform(t *testing.T) {
	n, hit := 100000, 0
	for i := 0; i < n; i++ {
		a, b := unit(1, int64(i), 7), unit(1, int64(i), 7)
		if a != b || a < 0 || a >= 1 {
			t.Fatalf("unit not deterministic/in range: %v %v", a, b)
		}
		if a < 0.25 {
			hit++
		}
	}
	if r := float64(hit) / float64(n); r < 0.24 || r > 0.26 {
		t.Fatalf("unit(<0.25) rate %.4f", r)
	}
	if unit(1, 5, 7) == unit(2, 5, 7) || unit(1, 5, 7) == unit(1, 5, 8) {
		t.Fatal("seed/salt not mixed in")
	}
}
