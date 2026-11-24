package jsonscan

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestAccepts(t *testing.T) {
	for _, in := range []string{
		`{}`, `[]`, `"x"`, `0`, `-0`, `1.5e+10`, `true`, `false`, `null`,
		`{"a":1,"b":[1,2,{"c":"d"}],"e":null}`,
		" \t\r\n{\"a\" : [ 1 , 2 ] }\n",
		`{"s":"\u00e9\ud83d\ude00\n\\\"\/"}`,
		`{"emoji":"😀","é":1}`,
		`{"a":{"a":{"a":1}}}`, // same key at different depths is fine
	} {
		if _, err := Validate([]byte(in), DefaultLimits()); err != nil {
			t.Errorf("rejected %q: %v", in, err)
		}
	}
}

func TestRejects(t *testing.T) {
	long := `"` + strings.Repeat("a", 5<<20) + `"`
	for name, in := range map[string]string{
		"empty":            ``,
		"dup key":          `{"a":1,"a":2}`,
		"dup via escape":   `{"a":1,"\u0061":2}`,
		"dup escaped both": `{"\u0061":1,"\u0061":2}`,
		"dup nested":       `{"x":{"k":1,"k":2}}`,
		"invalid utf8":     "{\"a\":\"\xff\"}",
		"truncated utf8":   "{\"a\":\"\xe2\x82\"}",
		"control char":     "{\"a\":\"\x01\"}",
		"raw newline":      "{\"a\":\"x\ny\"}",
		"lone high":        `{"a":"\ud83d"}`,
		"lone low":         `{"a":"\ude00"}`,
		"high then other":  `{"a":"\ud83d\u0041"}`,
		"BOM":              "\xef\xbb\xbf{}",
		"trailing":         `{} x`,
		"two values":       `{}{}`,
		"trailing comma":   `{"a":1,}`,
		"leading zero":     `{"a":01}`,
		"plus":             `{"a":+1}`,
		"bare dot":         `{"a":1.}`,
		"bad exp":          `{"a":1e}`,
		"single quote":     `{'a':1}`,
		"unquoted key":     `{a:1}`,
		"NaN":              `{"a":NaN}`,
		"bad escape":       `{"a":"\x"}`,
		"short u":          `{"a":"\u12"}`,
		"vtab ws":          "{\v}",
		"nbsp ws":          "{\u00a0}",
		"unterminated":     `{"a":"x`,
		"unterminated obj": `{"a":1`,
		"huge string":      `{"a":` + long + `}`,
		"float overflow":   `{"a":1e1000}`,
		"neg overflow":     `{"a":-1e999}`,
		"too deep":         strings.Repeat("[", 65) + strings.Repeat("]", 65),
	} {
		if _, err := Validate([]byte(in), DefaultLimits()); err == nil {
			t.Errorf("%s: accepted %.40q", name, in)
		}
	}
	if _, err := Validate([]byte(strings.Repeat("[", 64)+strings.Repeat("]", 64)), DefaultLimits()); err != nil {
		t.Errorf("depth 64 must be allowed: %v", err)
	}
}

func TestLimits(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxBytes = 10
	if _, err := Validate([]byte(`{"abcdefghij":1}`), lim); err == nil {
		t.Error("size limit")
	}
	lim = DefaultLimits()
	lim.MaxKeys = 3
	if _, err := Validate([]byte(`{"a":1,"b":2,"c":3}`), lim); err != nil {
		t.Error("exactly MaxKeys must pass")
	}
	if _, err := Validate([]byte(`{"a":1,"b":2,"c":3,"d":4}`), lim); err == nil {
		t.Error("key limit")
	}
	var many strings.Builder
	many.WriteByte('{')
	for i := 0; i < 5000; i++ {
		if i > 0 {
			many.WriteByte(',')
		}
		many.WriteString(`"k` + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + itoa(i) + `":1`)
	}
	many.WriteByte('}')
	if _, err := Validate([]byte(many.String()), DefaultLimits()); err == nil {
		t.Error("5000 keys must exceed the 4096 default")
	}
	if _, err := Validate([]byte(`{"a":`+strings.Repeat("9", 200)+`}`), DefaultLimits()); err == nil {
		t.Error("number length limit")
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestLargeObjectDuplicateDetectionUsesMap(t *testing.T) {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < 100; i++ {
		b.WriteString(`"k` + itoa(i) + `":1,`)
	}
	b.WriteString(`"k42":2}`)
	if _, err := Validate([]byte(b.String()), DefaultLimits()); err == nil {
		t.Fatal("duplicate beyond the small-set threshold missed")
	}
}

func TestNavigation(t *testing.T) {
	doc := []byte(`{"model":"gpt-4","st\u0072eam":true,"n":42,"messages":[{"role":"user","content":"hi \"there\""},{"role":"system","content":null}]}`)
	root, err := Validate(doc, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	m, ok := Lookup(doc, root, "model")
	if s, _ := StringValue(doc, m); !ok || s != "gpt-4" {
		t.Fatalf("model %q", s)
	}
	st, ok := Lookup(doc, root, "stream") // key written with an escape
	if v, bok := Bool(st); !ok || !bok || !v {
		t.Fatal("escaped key lookup")
	}
	n, _ := Lookup(doc, root, "n")
	if v, ok := Int(doc, n); !ok || v != 42 {
		t.Fatal("int")
	}
	if _, ok := Lookup(doc, root, "absent"); ok {
		t.Fatal("absent key found")
	}
	msgs, _ := Lookup(doc, root, "messages")
	var roles []string
	Elems(doc, msgs, func(i int, v Span) bool {
		r, _ := Lookup(doc, v, "role")
		s, _ := StringValue(doc, r)
		roles = append(roles, s)
		return true
	})
	if !reflect.DeepEqual(roles, []string{"user", "system"}) {
		t.Fatalf("roles %v", roles)
	}
	first := msgs
	Elems(doc, msgs, func(i int, v Span) bool { first = v; return false })
	c, _ := Lookup(doc, first, "content")
	if s, _ := StringValue(doc, c); s != `hi "there"` {
		t.Fatalf("content %q", s)
	}
	if string(root.Bytes(doc)) != string(doc) {
		t.Fatal("root span")
	}
}

func TestStringValueSurrogatePair(t *testing.T) {
	doc := []byte(`"a\ud83d\ude00b"`)
	sp, err := Validate(doc, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := StringValue(doc, sp); s != "a😀b" {
		t.Fatalf("%q", s)
	}
}

// allStrings collects every string value and object key, in document order,
// using the standard library as the reference parser.
func stdStrings(doc []byte) (out []string, dup bool, err error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	type frame struct {
		obj  bool
		keys map[string]bool
		want bool // next string token is a key
	}
	var st []frame
	for {
		tok, e := dec.Token()
		if e == io.EOF {
			return out, dup, nil
		}
		if e != nil {
			return nil, false, e
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				st = append(st, frame{obj: true, keys: map[string]bool{}, want: true})
				continue
			case '[':
				st = append(st, frame{})
				continue
			default:
				st = st[:len(st)-1]
			}
		case string:
			out = append(out, v)
			if n := len(st); n > 0 && st[n-1].obj && st[n-1].want {
				if st[n-1].keys[v] {
					dup = true
				}
				st[n-1].keys[v] = true
				st[n-1].want = false
				continue
			}
		}
		// a value finished: if inside an object the next token is a key
		if n := len(st); n > 0 && st[n-1].obj {
			st[n-1].want = true
		}
	}
}

func ourStrings(doc []byte, s Span, out *[]string) {
	switch s.Kind {
	case String:
		v, _ := StringValue(doc, s)
		*out = append(*out, v)
	case Object:
		Fields(doc, s, func(f Field) bool {
			*out = append(*out, string(decodeInto(nil, f.Key)))
			ourStrings(doc, f.Value, out)
			return true
		})
	case Array:
		Elems(doc, s, func(_ int, v Span) bool { ourStrings(doc, v, out); return true })
	}
}

// Differential property (also the fuzz oracle): whatever we accept, the
// standard library accepts, sees no duplicate keys, and decodes to exactly the
// same strings and keys. Any divergence would be a parser-differential finding.
func checkAgainstStd(t testing.TB, in []byte) {
	root, err := Validate(in, DefaultLimits())
	if err != nil {
		return
	}
	if !json.Valid(in) {
		t.Fatalf("we accept what encoding/json rejects: %q", in)
	}
	std, dup, err := stdStrings(in)
	if err != nil {
		t.Fatalf("std token stream failed on accepted input %q: %v", in, err)
	}
	if dup {
		t.Fatalf("accepted a document with duplicate keys: %q", in)
	}
	var ours []string
	ourStrings(in, root, &ours)
	if !reflect.DeepEqual(ours, std) {
		t.Fatalf("string view differs on %q\nours: %q\nstd:  %q", in, ours, std)
	}
}

func TestDifferentialCorpus(t *testing.T) {
	for _, in := range []string{
		`{"a":"x\u0000y","b":["\ud83d\ude00","é"],"c":{"d":"\\\"/"}}`,
		`[{"k":"v"},{"k":"w"}]`, `"\u00e9"`, `{"\u0061\u0062":"\u0063"}`,
	} {
		checkAgainstStd(t, []byte(in))
	}
}

func FuzzJSONScan(f *testing.F) {
	seeds := []string{`{}`, `{"a":1,"a":2}`, `{"a":"\ud83d\ude00"}`, `[1,2,{"x":[null,true]}]`, `{"\u0061":1,"a":2}`,
		"{\"a\":\"\xff\"}", `{"messages":[{"role":"user","content":"hi"}],"model":"m","stream":false}`, `-0.5e-3`, `{"a":"\ud800"}`}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		_, _ = Validate(in, DefaultLimits()) // never panics
	})
}

func FuzzJSONScanDiff(f *testing.F) {
	for _, s := range []string{`{"a":"b"}`, `{"a":["\u00e9",{"b":"c"}]}`, `["\ud83d\ude00"]`, `{"k":"\\n\n"}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) { checkAgainstStd(t, in) })
}

func FuzzNavigationNeverPanics(f *testing.F) {
	f.Add([]byte(`{"a":[1,{"b":"c"}],"d":"e"}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		root, err := Validate(in, DefaultLimits())
		if err != nil {
			return
		}
		var out []string
		ourStrings(in, root, &out)
		_, _ = Lookup(in, root, "a")
	})
}
