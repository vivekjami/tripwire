package openai

import (
	"errors"
	"testing"

	"github.com/vivekjami/tripwire/internal/jsonscan"
)

type rec struct{ got []string }

func (r *rec) Text(f TextField) error {
	r.got = append(r.got, f.Role+":"+kindName(f.Kind))
	return nil
}
func kindName(k FieldKind) string {
	return [...]string{"content", "part", "args", "toolname", "name", "refusal"}[k]
}

func TestParseValid(t *testing.T) {
	doc := []byte(`{"model":"gpt-4o","stream":true,"messages":[
	 {"role":"system","content":"s"},
	 {"role":"user","name":"bob","content":[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"url":"x"}}]},
	 {"role":"assistant","content":null,"tool_calls":[{"id":"1","type":"function","function":{"name":"f","arguments":"{\"a\":1}"}}]}]}`)
	r, err := ParseChatRequest(doc, jsonscan.DefaultLimits())
	if err != nil || r.Model != "gpt-4o" || !r.Stream {
		t.Fatalf("%v %+v", err, r)
	}
	var w rec
	if err := WalkRequest(r, &w); err != nil {
		t.Fatal(err)
	}
	// ordering within one message: content, name, refusal, function_call, tool_calls
	want := []string{"system:content", "user:part", "user:name", "assistant:toolname", "assistant:args"}
	if len(w.got) != len(want) {
		t.Fatalf("got %v", w.got)
	}
	for i := range want {
		if w.got[i] != want[i] {
			t.Fatalf("got %v want %v", w.got, want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for name, in := range map[string]string{
		"not json":      `{`,
		"array root":    `[]`,
		"no model":      `{"messages":[{"role":"user","content":"x"}]}`,
		"model number":  `{"model":1,"messages":[{"role":"user","content":"x"}]}`,
		"empty model":   `{"model":"","messages":[{"role":"user","content":"x"}]}`,
		"no messages":   `{"model":"m"}`,
		"empty msgs":    `{"model":"m","messages":[]}`,
		"msg not obj":   `{"model":"m","messages":["x"]}`,
		"bad role":      `{"model":"m","messages":[{"role":"root","content":"x"}]}`,
		"missing role":  `{"model":"m","messages":[{"content":"x"}]}`,
		"stream string": `{"model":"m","stream":"true","messages":[{"role":"user","content":"x"}]}`,
		"dup model":     `{"model":"a","model":"b","messages":[{"role":"user","content":"x"}]}`,
		"dup via esc":   `{"model":"a","model":"b","messages":[{"role":"user","content":"x"}]}`,
	} {
		_, err := ParseChatRequest([]byte(in), jsonscan.DefaultLimits())
		var ve *ValidationError
		if err == nil || !errors.As(err, &ve) {
			t.Errorf("%s: want ValidationError, got %v", name, err)
		}
	}
}

func TestWalkResponse(t *testing.T) {
	doc := []byte(`{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"hello","tool_calls":[{"function":{"name":"f","arguments":"{}"}}]},"finish_reason":"stop"}]}`)
	var w rec
	if err := WalkResponse(doc, jsonscan.DefaultLimits(), &w); err != nil {
		t.Fatal(err)
	}
	if len(w.got) != 3 || w.got[0] != "assistant:content" {
		t.Fatalf("%v", w.got)
	}
	for _, bad := range []string{`{`, `[]`, `{"choices":1}`, `{"id":1}`, `{"choices":[],"choices":[]}`} {
		if err := WalkResponse([]byte(bad), jsonscan.DefaultLimits(), NoopWalker{}); !errors.Is(err, ErrBadResponse) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

type blocker struct{}

func (blocker) Text(f TextField) error { return errors.New("blocked") }

func TestWalkerCanAbort(t *testing.T) {
	r, _ := ParseChatRequest([]byte(`{"model":"m","messages":[{"role":"user","content":"x"}]}`), jsonscan.DefaultLimits())
	if err := WalkRequest(r, blocker{}); err == nil {
		t.Fatal("walker error must propagate")
	}
}
