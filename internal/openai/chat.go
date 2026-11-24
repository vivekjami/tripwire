// Package openai parses OpenAI Chat Completions traffic on top of the strict
// scanner and exposes a role-aware field walker: the hook where detectors
// attach in Phase 2. In Phase 1 the walker is a no-op, so parsing cost is
// measured in isolation (IMPLEMENTATION_PLAN Phase 1 goal).
package openai

import (
	"errors"
	"fmt"

	"github.com/vivekjami/tripwire/internal/jsonscan"
)

// FieldKind says what a text-bearing field is.
type FieldKind uint8

// Text-bearing field kinds.
const (
	Content     FieldKind = iota // message.content as a string
	ContentPart                  // message.content[i].text
	ToolArgs                     // tool_calls[i].function.arguments (a JSON document inside a string)
	ToolName                     // tool_calls[i].function.name
	Name                         // message.name
	Refusal                      // message.refusal
)

// TextField locates one text-bearing JSON string in the document.
type TextField struct {
	Role  string
	Kind  FieldKind
	Index int           // message index (request) or choice index (response)
	Span  jsonscan.Span // the JSON string value (including quotes) in the document
}

// Walker receives every text-bearing field in document order. Returning an
// error aborts the walk (a Phase 2 detector uses this to block).
type Walker interface {
	Text(f TextField) error
}

// NoopWalker ignores every field.
type NoopWalker struct{}

// Text implements Walker.
func (NoopWalker) Text(TextField) error { return nil }

// Request is a validated chat-completions request.
type Request struct {
	Doc    []byte
	Root   jsonscan.Span
	Model  string
	Stream bool
}

// ValidationError is a client error (HTTP 400) with an OpenAI-style code.
type ValidationError struct{ Code, Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func bad(code, f string, a ...any) error { return &ValidationError{code, fmt.Sprintf(f, a...)} }

var validRoles = map[string]bool{"system": true, "developer": true, "user": true, "assistant": true, "tool": true, "function": true}

// ParseChatRequest strictly validates the body and extracts routing fields.
func ParseChatRequest(doc []byte, lim jsonscan.Limits) (*Request, error) {
	root, err := jsonscan.Validate(doc, lim)
	if err != nil {
		return nil, bad("invalid_json", "request body is not acceptable JSON: %v", err)
	}
	if root.Kind != jsonscan.Object {
		return nil, bad("invalid_request", "request body must be a JSON object")
	}
	r := &Request{Doc: doc, Root: root}
	m, ok := jsonscan.Lookup(doc, root, "model")
	if !ok || m.Kind != jsonscan.String {
		return nil, bad("invalid_model", "model must be a string")
	}
	r.Model, _ = jsonscan.StringValue(doc, m)
	if r.Model == "" || len(r.Model) > 256 {
		return nil, bad("invalid_model", "model must be 1-256 bytes")
	}
	if s, ok := jsonscan.Lookup(doc, root, "stream"); ok {
		v, isBool := jsonscan.Bool(s)
		if !isBool {
			return nil, bad("invalid_request", "stream must be a boolean")
		}
		r.Stream = v
	}
	msgs, ok := jsonscan.Lookup(doc, root, "messages")
	if !ok || msgs.Kind != jsonscan.Array {
		return nil, bad("invalid_messages", "messages must be a non-empty array")
	}
	n := 0
	var verr error
	jsonscan.Elems(doc, msgs, func(_ int, m jsonscan.Span) bool {
		n++
		if m.Kind != jsonscan.Object {
			verr = bad("invalid_messages", "each message must be an object")
			return false
		}
		role, ok := jsonscan.Lookup(doc, m, "role")
		rs, _ := jsonscan.StringValue(doc, role)
		if !ok || !validRoles[rs] {
			verr = bad("invalid_role", "message role must be one of system, developer, user, assistant, tool, function")
			return false
		}
		return true
	})
	if verr != nil {
		return nil, verr
	}
	if n == 0 {
		return nil, bad("invalid_messages", "messages must be a non-empty array")
	}
	return r, nil
}

// WalkRequest feeds every text-bearing request field to w.
func WalkRequest(r *Request, w Walker) error {
	msgs, _ := jsonscan.Lookup(r.Doc, r.Root, "messages")
	var err error
	jsonscan.Elems(r.Doc, msgs, func(i int, m jsonscan.Span) bool {
		role, _ := jsonscan.Lookup(r.Doc, m, "role")
		rs, _ := jsonscan.StringValue(r.Doc, role)
		err = walkMessage(r.Doc, m, rs, i, w)
		return err == nil
	})
	return err
}

// walkMessage covers request messages and response choices[].message alike.
func walkMessage(doc []byte, m jsonscan.Span, role string, idx int, w Walker) error {
	emit := func(k FieldKind, s jsonscan.Span) error {
		if s.Kind != jsonscan.String {
			return nil
		}
		return w.Text(TextField{Role: role, Kind: k, Index: idx, Span: s})
	}
	if c, ok := jsonscan.Lookup(doc, m, "content"); ok {
		switch c.Kind {
		case jsonscan.String:
			if err := emit(Content, c); err != nil {
				return err
			}
		case jsonscan.Array:
			var err error
			jsonscan.Elems(doc, c, func(_ int, part jsonscan.Span) bool {
				if part.Kind != jsonscan.Object {
					return true
				}
				if t, ok := jsonscan.Lookup(doc, part, "text"); ok {
					err = emit(ContentPart, t)
				}
				return err == nil
			})
			if err != nil {
				return err
			}
		}
	}
	for _, f := range []struct {
		key  string
		kind FieldKind
	}{{"name", Name}, {"refusal", Refusal}} {
		if s, ok := jsonscan.Lookup(doc, m, f.key); ok {
			if err := emit(f.kind, s); err != nil {
				return err
			}
		}
	}
	if fc, ok := jsonscan.Lookup(doc, m, "function_call"); ok && fc.Kind == jsonscan.Object { // legacy
		if err := walkFunction(doc, fc, emit); err != nil {
			return err
		}
	}
	if tcs, ok := jsonscan.Lookup(doc, m, "tool_calls"); ok && tcs.Kind == jsonscan.Array {
		var err error
		jsonscan.Elems(doc, tcs, func(_ int, tc jsonscan.Span) bool {
			if tc.Kind != jsonscan.Object {
				return true
			}
			if fn, ok := jsonscan.Lookup(doc, tc, "function"); ok && fn.Kind == jsonscan.Object {
				err = walkFunction(doc, fn, emit)
			}
			return err == nil
		})
		return err
	}
	return nil
}

func walkFunction(doc []byte, fn jsonscan.Span, emit func(FieldKind, jsonscan.Span) error) error {
	if s, ok := jsonscan.Lookup(doc, fn, "name"); ok {
		if err := emit(ToolName, s); err != nil {
			return err
		}
	}
	if s, ok := jsonscan.Lookup(doc, fn, "arguments"); ok {
		return emit(ToolArgs, s)
	}
	return nil
}

// ErrBadResponse marks an upstream body that is not a well-formed chat response.
var ErrBadResponse = errors.New("openai: malformed upstream response")

// WalkResponse validates a non-streaming response and feeds choices[].message
// text to w. The caller forwards the original bytes only if this succeeds.
func WalkResponse(doc []byte, lim jsonscan.Limits, w Walker) error {
	root, err := jsonscan.Validate(doc, lim)
	if err != nil || root.Kind != jsonscan.Object {
		return fmt.Errorf("%w: %v", ErrBadResponse, err)
	}
	choices, ok := jsonscan.Lookup(doc, root, "choices")
	if !ok || choices.Kind != jsonscan.Array {
		return fmt.Errorf("%w: choices missing", ErrBadResponse)
	}
	var werr error
	jsonscan.Elems(doc, choices, func(i int, ch jsonscan.Span) bool {
		if ch.Kind != jsonscan.Object {
			return true
		}
		if m, ok := jsonscan.Lookup(doc, ch, "message"); ok && m.Kind == jsonscan.Object {
			werr = walkMessage(doc, m, "assistant", i, w)
		}
		return werr == nil
	})
	return werr
}
