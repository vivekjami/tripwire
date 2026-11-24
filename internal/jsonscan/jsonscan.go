// Package jsonscan is the gateway's strict JSON scanner, v1 (WP1.3): a
// validating single-pass parser that reports byte spans instead of building a
// tree. "Strict" is the point: the gateway forwards only bytes it has validated
// (ADR-27), so anything on which parsers could disagree is rejected here:
//
//   - duplicate object keys (compared after decoding escapes);
//   - invalid UTF-8, unescaped control characters, lone surrogate escapes;
//   - a leading BOM, trailing data, non-JSON whitespace, bad number grammar;
//   - documents beyond the depth, size, key-count and string-length limits.
//
// Navigation helpers assume bytes that already passed Validate. Streaming
// delta paths, the resumable escape decoder and the splice API are v2 (WP1.5).
package jsonscan

import (
	"fmt"
	"strconv"
	"unicode/utf8"
)

// Kind is the JSON type of a Span.
type Kind uint8

// JSON kinds.
const (
	Invalid Kind = iota
	Object
	Array
	String
	Number
	True
	False
	Null
)

// Span is a value's byte range [Start, End) in the validated document. For
// strings the range includes both quotes.
type Span struct {
	Start, End int
	Kind       Kind
}

// Bytes returns the raw bytes of the value.
func (s Span) Bytes(doc []byte) []byte { return doc[s.Start:s.End] }

// Limits bound a document (ARCHITECTURE §14.2).
type Limits struct {
	MaxBytes  int // document size
	MaxDepth  int
	MaxKeys   int // keys per object
	MaxString int // bytes of one raw string
	MaxNumber int // bytes of one number literal
}

// DefaultLimits are the architecture defaults.
func DefaultLimits() Limits {
	return Limits{MaxBytes: 8 << 20, MaxDepth: 64, MaxKeys: 4096, MaxString: 4 << 20, MaxNumber: 128}
}

// Error describes why a document was rejected.
type Error struct {
	Offset int
	Msg    string
}

func (e *Error) Error() string { return fmt.Sprintf("json: %s at byte %d", e.Msg, e.Offset) }

// Validate checks doc against the strict rules and limits and returns the root span.
func Validate(doc []byte, lim Limits) (Span, error) {
	if lim.MaxBytes > 0 && len(doc) > lim.MaxBytes {
		return Span{}, &Error{0, "document exceeds size limit"}
	}
	p := parser{b: doc, lim: lim}
	p.ws()
	root, err := p.value(0)
	if err != nil {
		return Span{}, err
	}
	p.ws()
	if p.i != len(doc) {
		return Span{}, &Error{p.i, "trailing data after the top-level value"}
	}
	return root, nil
}

type parser struct {
	b       []byte
	i       int
	lim     Limits
	scratch []byte
}

func (p *parser) fail(msg string) error { return &Error{p.i, msg} }

func (p *parser) ws() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (Span, error) {
	if p.i >= len(p.b) {
		return Span{}, p.fail("unexpected end of input")
	}
	start := p.i
	switch c := p.b[p.i]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		if err := p.str(); err != nil {
			return Span{}, err
		}
		return Span{start, p.i, String}, nil
	case c == '-' || c >= '0' && c <= '9':
		if err := p.number(); err != nil {
			return Span{}, err
		}
		return Span{start, p.i, Number}, nil
	case c == 't':
		return p.lit("true", True)
	case c == 'f':
		return p.lit("false", False)
	case c == 'n':
		return p.lit("null", Null)
	}
	return Span{}, p.fail("unexpected character")
}

func (p *parser) lit(s string, k Kind) (Span, error) {
	if p.i+len(s) > len(p.b) || string(p.b[p.i:p.i+len(s)]) != s {
		return Span{}, p.fail("invalid literal")
	}
	st := p.i
	p.i += len(s)
	return Span{st, p.i, k}, nil
}

func (p *parser) number() error {
	st := p.i
	if p.b[p.i] == '-' {
		p.i++
	}
	if p.i >= len(p.b) {
		return p.fail("bad number")
	}
	switch {
	case p.b[p.i] == '0':
		p.i++
	case p.b[p.i] >= '1' && p.b[p.i] <= '9':
		for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
			p.i++
		}
	default:
		return p.fail("bad number")
	}
	if p.i < len(p.b) && p.b[p.i] == '.' {
		p.i++
		if !p.digits() {
			return p.fail("bad number: digits required after '.'")
		}
	}
	if p.i < len(p.b) && (p.b[p.i] == 'e' || p.b[p.i] == 'E') {
		p.i++
		if p.i < len(p.b) && (p.b[p.i] == '+' || p.b[p.i] == '-') {
			p.i++
		}
		if !p.digits() {
			return p.fail("bad number: digits required in exponent")
		}
	}
	if p.lim.MaxNumber > 0 && p.i-st > p.lim.MaxNumber {
		return &Error{st, "number literal too long"}
	}
	// A literal that overflows float64 (1e1000) is valid JSON grammar but means
	// +Inf, an error or a bignum depending on the parser: reject it.
	if _, err := strconv.ParseFloat(string(p.b[st:p.i]), 64); err != nil {
		return &Error{st, "number out of range"}
	}
	return nil
}

func (p *parser) digits() bool {
	st := p.i
	for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
		p.i++
	}
	return p.i > st
}

// str validates a string starting at the opening quote and leaves p.i after the closing quote.
func (p *parser) str() error {
	st := p.i
	p.i++
	for p.i < len(p.b) {
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			if p.lim.MaxString > 0 && p.i-st > p.lim.MaxString {
				return &Error{st, "string exceeds length limit"}
			}
			return nil
		case c < 0x20:
			return p.fail("unescaped control character in string")
		case c == '\\':
			if err := p.escape(); err != nil {
				return err
			}
		case c < utf8.RuneSelf:
			p.i++
		default:
			r, n := utf8.DecodeRune(p.b[p.i:])
			if r == utf8.RuneError && n <= 1 {
				return p.fail("invalid UTF-8")
			}
			p.i += n
		}
	}
	return p.fail("unterminated string")
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var r rune
	for _, c := range b[:4] {
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

// escape validates one escape at p.i (a backslash). Surrogate escapes must come
// in valid high+low pairs: a lone surrogate decodes differently in different
// parsers (U+FFFD vs error vs raw bytes), which is exactly what an attacker uses.
func (p *parser) escape() error {
	p.i++
	if p.i >= len(p.b) {
		return p.fail("unterminated escape")
	}
	switch p.b[p.i] {
	case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		p.i++
		return nil
	case 'u':
		r, ok := hex4(p.b[p.i+1:])
		if !ok {
			return p.fail("bad \\u escape")
		}
		p.i += 5
		switch {
		case r >= 0xD800 && r <= 0xDBFF:
			if p.i+1 < len(p.b) && p.b[p.i] == '\\' && p.b[p.i+1] == 'u' {
				if lo, ok := hex4(p.b[p.i+2:]); ok && lo >= 0xDC00 && lo <= 0xDFFF {
					p.i += 6
					return nil
				}
			}
			return p.fail("lone high surrogate escape")
		case r >= 0xDC00 && r <= 0xDFFF:
			return p.fail("lone low surrogate escape")
		}
		return nil
	}
	return p.fail("invalid escape")
}

func (p *parser) object(depth int) (Span, error) {
	st := p.i
	if depth+1 > p.lim.MaxDepth && p.lim.MaxDepth > 0 {
		return Span{}, p.fail("nesting too deep")
	}
	p.i++
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		return Span{st, p.i, Object}, nil
	}
	var seen keySet
	for {
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			return Span{}, p.fail("object key must be a string")
		}
		ks := p.i
		if err := p.str(); err != nil {
			return Span{}, err
		}
		key := p.decodeKey(p.b[ks+1 : p.i-1])
		if p.lim.MaxKeys > 0 && seen.len() >= p.lim.MaxKeys {
			return Span{}, &Error{ks, "too many keys in object"}
		}
		if !seen.add(key) {
			return Span{}, &Error{ks, "duplicate object key"}
		}
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return Span{}, p.fail("expected ':'")
		}
		p.i++
		p.ws()
		if _, err := p.value(depth + 1); err != nil {
			return Span{}, err
		}
		p.ws()
		if p.i >= len(p.b) {
			return Span{}, p.fail("unterminated object")
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return Span{st, p.i, Object}, nil
		default:
			return Span{}, p.fail("expected ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (Span, error) {
	st := p.i
	if depth+1 > p.lim.MaxDepth && p.lim.MaxDepth > 0 {
		return Span{}, p.fail("nesting too deep")
	}
	p.i++
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == ']' {
		p.i++
		return Span{st, p.i, Array}, nil
	}
	for {
		p.ws()
		if _, err := p.value(depth + 1); err != nil {
			return Span{}, err
		}
		p.ws()
		if p.i >= len(p.b) {
			return Span{}, p.fail("unterminated array")
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return Span{st, p.i, Array}, nil
		default:
			return Span{}, p.fail("expected ',' or ']'")
		}
	}
}

// decodeKey returns the decoded form of raw (already validated) key bytes.
func (p *parser) decodeKey(raw []byte) string {
	for _, c := range raw {
		if c == '\\' {
			p.scratch = decodeInto(p.scratch[:0], raw)
			return string(p.scratch)
		}
	}
	return string(raw)
}

type keySet struct {
	small []string
	big   map[string]struct{}
}

func (k *keySet) len() int {
	if k.big != nil {
		return len(k.big)
	}
	return len(k.small)
}

func (k *keySet) add(s string) bool {
	if k.big != nil {
		if _, dup := k.big[s]; dup {
			return false
		}
		k.big[s] = struct{}{}
		return true
	}
	for _, e := range k.small {
		if e == s {
			return false
		}
	}
	k.small = append(k.small, s)
	if len(k.small) > 16 {
		k.big = make(map[string]struct{}, 64)
		for _, e := range k.small {
			k.big[e] = struct{}{}
		}
		k.small = nil
	}
	return true
}

// decodeInto appends the decoded content of a validated JSON string body
// (without quotes) to dst.
func decodeInto(dst, raw []byte) []byte {
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c != '\\' {
			dst = append(dst, c)
			continue
		}
		i++
		switch raw[i] {
		case '"', '\\', '/':
			dst = append(dst, raw[i])
		case 'b':
			dst = append(dst, '\b')
		case 'f':
			dst = append(dst, '\f')
		case 'n':
			dst = append(dst, '\n')
		case 'r':
			dst = append(dst, '\r')
		case 't':
			dst = append(dst, '\t')
		case 'u':
			r, _ := hex4(raw[i+1:])
			i += 4
			if r >= 0xD800 && r <= 0xDBFF && i+6 < len(raw)+0 && raw[i+1] == '\\' && raw[i+2] == 'u' {
				lo, _ := hex4(raw[i+3:])
				i += 6
				r = 0x10000 + (r-0xD800)<<10 + (lo - 0xDC00)
			}
			dst = utf8.AppendRune(dst, r)
		}
	}
	return dst
}

// ---- navigation over validated bytes ----------------------------------------

// StringValue decodes a String span into a Go string.
func StringValue(doc []byte, s Span) (string, bool) {
	if s.Kind != String {
		return "", false
	}
	raw := doc[s.Start+1 : s.End-1]
	for _, c := range raw {
		if c == '\\' {
			return string(decodeInto(nil, raw)), true
		}
	}
	return string(raw), true
}

// Bool returns the value of a True/False span.
func Bool(s Span) (v, ok bool) { return s.Kind == True, s.Kind == True || s.Kind == False }

// Int parses a Number span as an int64 (ok=false if it is not an integer literal).
func Int(doc []byte, s Span) (int64, bool) {
	if s.Kind != Number {
		return 0, false
	}
	n, err := strconv.ParseInt(string(doc[s.Start:s.End]), 10, 64)
	return n, err == nil
}

// Field is one object member.
type Field struct {
	Key   []byte // raw key content between the quotes (still escaped)
	Value Span
}

// Fields calls fn for each member of an Object span in document order until fn returns false.
func Fields(doc []byte, obj Span, fn func(Field) bool) {
	if obj.Kind != Object {
		return
	}
	p := parser{b: doc, i: obj.Start + 1, lim: Limits{}}
	p.ws()
	if p.i < obj.End && doc[p.i] == '}' {
		return
	}
	for p.i < obj.End {
		p.ws()
		ks := p.i
		if p.str() != nil {
			return
		}
		key := doc[ks+1 : p.i-1]
		p.ws()
		p.i++ // ':'
		p.ws()
		v, err := p.value(0)
		if err != nil {
			return
		}
		if !fn(Field{key, v}) {
			return
		}
		p.ws()
		if p.i >= obj.End || doc[p.i] == '}' {
			return
		}
		p.i++ // ','
	}
}

// Lookup finds a member by decoded key name.
func Lookup(doc []byte, obj Span, name string) (Span, bool) {
	var out Span
	var found bool
	Fields(doc, obj, func(f Field) bool {
		if keyEquals(f.Key, name) {
			out, found = f.Value, true
			return false
		}
		return true
	})
	return out, found
}

func keyEquals(raw []byte, name string) bool {
	for _, c := range raw {
		if c == '\\' {
			return string(decodeInto(nil, raw)) == name
		}
	}
	return string(raw) == name
}

// Elems calls fn for each element of an Array span until fn returns false.
func Elems(doc []byte, arr Span, fn func(i int, v Span) bool) {
	if arr.Kind != Array {
		return
	}
	p := parser{b: doc, i: arr.Start + 1, lim: Limits{}}
	p.ws()
	if p.i < arr.End && doc[p.i] == ']' {
		return
	}
	for idx := 0; p.i < arr.End; idx++ {
		p.ws()
		v, err := p.value(0)
		if err != nil || !fn(idx, v) {
			return
		}
		p.ws()
		if p.i >= arr.End || doc[p.i] == ']' {
			return
		}
		p.i++
	}
}
