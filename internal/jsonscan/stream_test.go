package jsonscan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

const chunk = `{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":"Hello \"w\" é"},"finish_reason":null}]}`

func newStreamScanner() *Scanner {
	lim := DefaultLimits()
	lim.AllowLoneSurrogates = true
	var s Scanner
	s.Init(lim)
	return &s
}

func TestLocatorFindsDeltaPaths(t *testing.T) {
	doc := []byte(`{"choices":[
	 {"index":0,"delta":{"role":"assistant","content":"A","refusal":"R"}},
	 {"index":1,"delta":{"tool_calls":[{"index":0,"id":"x","function":{"name":"fn","arguments":"{\"a\":"}},{"index":1,"function":{"arguments":"2}"}}]}},
	 {"index":2,"message":{"content":[{"type":"text","text":"P1"},{"type":"image_url","image_url":{"url":"u"}}],"function_call":{"name":"old","arguments":"{}"}}}
	]}`)
	s := newStreamScanner()
	if _, err := s.Scan(doc); err != nil {
		t.Fatal(err)
	}
	type L struct {
		c, tool int32
		k       uint8
		text    string
	}
	var got []L
	for _, l := range s.Locs {
		v, _ := StringValue(doc, Span{int(l.Start), int(l.End), String})
		got = append(got, L{l.Choice, l.Tool, l.Kind, v})
	}
	want := []L{
		{0, -1, LocContent, "A"}, {0, -1, LocRefusal, "R"},
		{1, 0, LocToolName, "fn"}, {1, 0, LocToolArgs, `{"a":`}, {1, 1, LocToolArgs, "2}"},
		{2, -1, LocPart, "P1"}, {2, -1, LocToolName, "old"}, {2, -1, LocToolArgs, "{}"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("loc %d: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestLocatorIgnoresLookalikes(t *testing.T) {
	for _, in := range []string{
		`{"content":"top-level"}`,
		`{"choices":[{"delta":{"meta":{"content":"nested"}}}]}`,
		`{"x":{"choices":[{"delta":{"content":"not-root"}}]}}`,
		`{"choices":[{"delta":{"content":null}}]}`,
		`{"choices":[{"delta":{"content":5}}]}`,
		`{"choices":[{"other":{"content":"x"}}]}`,
	} {
		s := newStreamScanner()
		if _, err := s.Scan([]byte(in)); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if len(s.Locs) != 0 {
			t.Errorf("%s: unexpected locs %+v", in, s.Locs)
		}
	}
}

func TestScanAllowsLoneSurrogateOnlyWhenConfigured(t *testing.T) {
	doc := []byte(`{"choices":[{"delta":{"content":"\ud83d"}}]}`)
	if _, err := Validate(doc, DefaultLimits()); err == nil {
		t.Fatal("strict mode must reject")
	}
	s := newStreamScanner()
	if _, err := s.Scan(doc); err != nil || len(s.Locs) != 1 {
		t.Fatalf("stream mode must accept: %v %+v", err, s.Locs)
	}
}

func TestScanZeroAllocs(t *testing.T) {
	doc := []byte(chunk)
	s := newStreamScanner()
	if _, err := s.Scan(doc); err != nil { // warm up the reusable buffers
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(200, func() { _, _ = s.Scan(doc) }); n != 0 {
		t.Fatalf("Scan allocates %.1f times per call; the hot path must be allocation-free", n)
	}
	// keys with escapes and duplicate-key checks must stay allocation-free too
	doc2 := []byte(`{"id":"x","choices":[{"delta":{"content":"hi","refusal":null}}],"a":1,"b":2,"c":3}`)
	if _, err := s.Scan(doc2); err != nil || len(s.Locs) != 1 {
		t.Fatalf("%v %+v", err, s.Locs)
	}
	if n := testing.AllocsPerRun(200, func() { _, _ = s.Scan(doc2) }); n != 0 {
		t.Fatalf("escaped-key Scan allocates %.1f times per call", n)
	}
}

func TestDuplicateKeyStillRejectedInLocatedShapes(t *testing.T) {
	s := newStreamScanner()
	for _, in := range []string{
		`{"choices":[{"delta":{"content":"a","content":"b"}}]}`,
		`{"choices":[{"delta":{"content":"a"},"delta":{"content":"b"}}]}`,
		`{"choices":[],"choices":[]}`,
	} {
		if _, err := s.Scan([]byte(in)); err == nil {
			t.Errorf("accepted %s", in)
		}
	}
}

func BenchmarkJSONScanDelta(b *testing.B) {
	doc := []byte(chunk)
	s := newStreamScanner()
	_, _ = s.Scan(doc)
	b.SetBytes(int64(len(doc)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := s.Scan(doc); err != nil {
			b.Fatal(err)
		}
	}
}

// ---- Unescaper ---------------------------------------------------------------

func stdDecode(t testing.TB, body string) (string, bool) {
	var s string
	if err := json.Unmarshal([]byte(`"`+body+`"`), &s); err != nil {
		return "", false
	}
	return s, true
}

func TestUnescaperSplitSurrogatePairAcrossFeeds(t *testing.T) {
	var u Unescaper
	out, err := u.Feed(nil, []byte(`a\ud83d`))
	if err != nil || string(out) != "a" || !u.Pending() {
		t.Fatalf("%q %v pending=%v", out, err, u.Pending())
	}
	out, err = u.Feed(out, []byte(`\ude00b`))
	if err != nil || string(out) != "a😀b" || u.Pending() {
		t.Fatalf("%q %v", out, err)
	}
}

func TestUnescaperSplitsAtEveryBoundary(t *testing.T) {
	body := `x\"\\\/\b\f\n\r\té€😀é€😀z`
	want, ok := stdDecode(t, body)
	if !ok {
		t.Fatal("std rejects the fixture")
	}
	for cut := 0; cut <= len(body); cut++ {
		var u Unescaper
		out, err := u.Feed(nil, []byte(body[:cut]))
		if err == nil {
			out, err = u.Feed(out, []byte(body[cut:]))
		}
		if err == nil {
			out, err = u.Flush(out)
		}
		if err != nil || string(out) != want {
			t.Fatalf("cut %d: %q err=%v, want %q", cut, out, err, want)
		}
	}
	// one byte at a time
	var u Unescaper
	var out []byte
	for i := 0; i < len(body); i++ {
		out, _ = u.Feed(out, []byte{body[i]})
	}
	out, _ = u.Flush(out)
	if string(out) != want {
		t.Fatalf("bytewise: %q", out)
	}
}

func TestUnescaperLoneSurrogatesAndErrors(t *testing.T) {
	var u Unescaper
	out, _ := u.Feed(nil, []byte(`\ud83dx`))
	out, _ = u.Flush(out)
	if string(out) != "�x" {
		t.Fatalf("lone high: %q", out)
	}
	u.Reset()
	out, _ = u.Feed(nil, []byte(`\ude00`))
	if string(out) != "�" {
		t.Fatalf("lone low: %q", out)
	}
	u.Reset()
	out, _ = u.Feed(nil, []byte(`\ud83d`))
	out, _ = u.Flush(out)
	if string(out) != "�" {
		t.Fatalf("trailing high: %q", out)
	}
	for _, bad := range []string{`\q`, `\u12G4`, "\xff", "\xc3\x28"} {
		var u Unescaper
		if _, err := u.Feed(nil, []byte(bad)); err == nil {
			if _, err = u.Flush(nil); err == nil {
				t.Errorf("accepted %q", bad)
			}
		}
	}
	u.Reset()
	if _, _ = u.Feed(nil, []byte(`ab\u12`)); !u.Pending() {
		t.Fatal("half escape must be pending")
	}
	if _, err := u.Flush(nil); err == nil {
		t.Fatal("flush with a half escape must fail")
	}
}

func FuzzUnescaper(f *testing.F) {
	for _, s := range []string{`abc`, `😀`, `éé`, `a\nb`, `\ud83d`, "\xf0\x9f\x98\x80"} {
		f.Add(s, uint8(3))
	}
	f.Fuzz(func(t *testing.T, body string, cut uint8) {
		// whole decode must equal chunked decode, for any split point, whenever both succeed
		var whole Unescaper
		w, werr := whole.Feed(nil, []byte(body))
		if werr == nil {
			w, werr = whole.Flush(w)
		}
		c := int(cut) % (len(body) + 1)
		var part Unescaper
		p, perr := part.Feed(nil, []byte(body[:c]))
		if perr == nil {
			p, perr = part.Feed(p, []byte(body[c:]))
		}
		if perr == nil {
			p, perr = part.Flush(p)
		}
		if (werr == nil) != (perr == nil) || (werr == nil && !bytes.Equal(w, p)) {
			t.Fatalf("split at %d changed the result: whole=%q/%v split=%q/%v", c, w, werr, p, perr)
		}
		if werr == nil && !utf8.Valid(w) {
			t.Fatalf("decoder emitted invalid UTF-8: %q", w)
		}
		// agree with the standard library when the standard library accepts and there are no lone surrogates
		if want, ok := stdDecode(t, body); ok && werr == nil && !strings.ContainsRune(want, utf8.RuneError) && string(w) != want {
			t.Fatalf("differs from encoding/json: %q vs %q for %q", w, want, body)
		}
	})
}

// ---- splice ----------------------------------------------------------------------

func TestDecodeMapAndRawRange(t *testing.T) {
	raw := []byte(`abé😀é\n!`)
	dec, offs, err := DecodeMap(nil, nil, raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != "abé😀é\n!" || len(offs) != len(dec)+1 {
		t.Fatalf("%q %d/%d", dec, len(offs), len(dec))
	}
	// replace the emoji (decoded bytes 4..8) -> the whole 12-byte pair escape
	s, e := RawRange(offs, 4, 8)
	if string(raw[s:e]) != `😀` {
		t.Fatalf("emoji range -> %q", raw[s:e])
	}
	// a range ending inside a multi-byte char expands to the whole char
	s, e = RawRange(offs, 2, 3)
	if string(raw[s:e]) != `é` {
		t.Fatalf("partial char range -> %q", raw[s:e])
	}
	s, e = RawRange(offs, 0, len(dec))
	if s != 0 || e != len(raw) {
		t.Fatalf("whole range -> %d,%d", s, e)
	}
}

func TestSpliceRewritesOnlyTheTarget(t *testing.T) {
	doc := []byte(chunk)
	s := newStreamScanner()
	if _, err := s.Scan(doc); err != nil {
		t.Fatal(err)
	}
	l := s.Locs[0]
	body := doc[l.Start+1 : l.End-1]
	dec, offs, _ := DecodeMap(nil, nil, body)
	i := strings.Index(string(dec), "w")
	rs, re := RawRange(offs, i-1, i+2) // the quoted "w"
	out, err := Splice(nil, doc, []Edit{{int(l.Start) + 1 + rs, int(l.Start) + 1 + re, AppendEscaped(nil, []byte(`[X]`))}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(out, DefaultLimits()); err != nil {
		t.Fatalf("spliced doc invalid: %v\n%s", err, out)
	}
	s2 := newStreamScanner()
	_, _ = s2.Scan(out)
	got, _ := StringValue(out, Span{int(s2.Locs[0].Start), int(s2.Locs[0].End), String})
	if got != "Hello [X] é" {
		t.Fatalf("got %q", got)
	}
	// bytes outside the edit are untouched
	if !bytes.HasPrefix(out, doc[:int(l.Start)+1+rs]) || !bytes.HasSuffix(out, doc[int(l.Start)+1+re:]) {
		t.Fatal("splice modified bytes outside the edit")
	}
	if _, err := Splice(nil, doc, []Edit{{5, 10, nil}, {8, 12, nil}}); err == nil {
		t.Fatal("overlapping edits accepted")
	}
	if _, err := Splice(nil, doc, []Edit{{0, len(doc) + 1, nil}}); err == nil {
		t.Fatal("out of range edit accepted")
	}
}

func TestAppendEscapedRoundTrip(t *testing.T) {
	for _, s := range []string{"plain", "q\"b\\s/", "ctl\x00\x01\x1f\n\r\t", "é€😀", "\xff bad"} {
		esc := AppendEscaped(nil, []byte(s))
		want := strings.ToValidUTF8(s, "�")
		got, ok := stdDecode(t, string(esc))
		if !ok || got != want {
			t.Errorf("%q -> %q -> %q (ok=%v)", s, esc, got, ok)
		}
	}
}

// FuzzDeltaRewriter: build an event around arbitrary text, splice a replacement
// over an arbitrary rune range through the position map, and require that
// parsing the result gives exactly the expected string.
func FuzzDeltaRewriter(f *testing.F) {
	f.Add("hello wörld 😀!", "[R]", uint8(2), uint8(5), true)
	f.Add("a\"b\\c\nd", "", uint8(1), uint8(4), false)
	f.Add("😀😀😀", "x", uint8(1), uint8(2), true)
	f.Fuzz(func(t *testing.T, text, repl string, a, b uint8, escapeAll bool) {
		text, repl = strings.ToValidUTF8(text, "?"), strings.ToValidUTF8(repl, "?")
		runes := []rune(text)
		i, j := int(a)%(len(runes)+1), int(b)%(len(runes)+1)
		if i > j {
			i, j = j, i
		}
		// body: escape non-ASCII as \u (with surrogate pairs) when escapeAll
		var body []byte
		for _, r := range runes {
			switch {
			case escapeAll && r >= 0x80:
				if r >= 0x10000 {
					r -= 0x10000
					body = append(body, []byte(`\u`+hex4s(0xD800+(r>>10))+`\u`+hex4s(0xDC00+(r&0x3FF)))...)
				} else {
					body = append(body, []byte(`\u`+hex4s(r))...)
				}
			default:
				body = AppendEscaped(body, []byte(string(r)))
			}
		}
		doc := append(append([]byte(`{"choices":[{"delta":{"content":"`), body...), `"}}]}`...)
		sc := newStreamScanner()
		if _, err := sc.Scan(doc); err != nil || len(sc.Locs) != 1 {
			t.Fatalf("setup scan: %v %d\n%s", err, len(sc.Locs), doc)
		}
		l := sc.Locs[0]
		dec, offs, err := DecodeMap(nil, nil, doc[l.Start+1:l.End-1])
		if err != nil || string(dec) != text {
			t.Fatalf("DecodeMap: %v %q vs %q", err, dec, text)
		}
		ba, bb := len(string(runes[:i])), len(string(runes[:j]))
		rs, re := RawRange(offs, ba, bb)
		base := int(l.Start) + 1
		out, err := Splice(nil, doc, []Edit{{base + rs, base + re, AppendEscaped(nil, []byte(repl))}})
		if err != nil {
			t.Fatal(err)
		}
		sc2 := newStreamScanner()
		if _, err := sc2.Scan(out); err != nil || len(sc2.Locs) != 1 {
			t.Fatalf("rewritten doc invalid: %v\n%s", err, out)
		}
		l2 := sc2.Locs[0]
		got, _ := StringValue(out, Span{int(l2.Start), int(l2.End), String})
		want := string(runes[:i]) + repl + string(runes[j:])
		if got != want {
			t.Fatalf("splice then parse != expected\n got %q\nwant %q\n doc %s", got, want, doc)
		}
	})
}

func hex4s(r rune) string {
	const h = "0123456789abcdef"
	return string([]byte{h[r>>12&0xF], h[r>>8&0xF], h[r>>4&0xF], h[r&0xF]})
}
