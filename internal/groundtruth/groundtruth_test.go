package groundtruth

import (
	"path/filepath"
	"testing"
	"unicode/utf16"
)

func TestDecodeJSONStringLoneSurrogates(t *testing.T) {
	// U+1F600 split across two events as lone surrogate escapes.
	hi, err := DecodeJSONString([]byte(`"a\ud83d"`))
	if err != nil {
		t.Fatal(err)
	}
	lo, err := DecodeJSONString([]byte(`"\ude00b"`))
	if err != nil {
		t.Fatal(err)
	}
	got := UnitsToString(append(hi, lo...))
	if got != "a\U0001F600b" {
		t.Fatalf("got %q", got)
	}
}

func TestDecodeJSONStringEscapesAndUTF8(t *testing.T) {
	u, err := DecodeJSONString([]byte(`"x\n\"\\\/é€😀"`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := UnitsToString(u), "x\n\"\\/é€😀"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestDecodeJSONStringErrors(t *testing.T) {
	for _, in := range []string{`abc`, `"abc`, `"\q"`, `"\u12"`, `"\u12zz"`, `"\`, "\"\xff\""} {
		if _, err := DecodeJSONString([]byte(in)); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func FuzzDecodeJSONString(f *testing.F) {
	f.Add(`"hello"`)
	f.Add(`"😀"`)
	f.Add(`"\ud83d"`)
	f.Fuzz(func(t *testing.T, s string) {
		u, err := DecodeJSONString([]byte(s))
		if err != nil {
			return
		}
		_ = UnitsToString(u)
		_ = utf16.IsSurrogate
	})
}

func TestCheckLeakAndAlter(t *testing.T) {
	gt := &Stream{
		Spans: []Span{{Class: "PCI.PAN", Value: "4111 1111 1111 1111", Norm: "4111111111111111", Hash: "h"}},
	}
	if r := Check(gt, "pay with 4111 1111 1111 1111 now"); len(r.Leaks) != 1 {
		t.Fatalf("want leak, got %+v", r)
	}
	if r := Check(gt, "pay with 4111111111111111 now"); len(r.Leaks) != 1 {
		t.Fatalf("want normalized leak, got %+v", r)
	}
	if r := Check(gt, "pay with [REDACTED:PCI.PAN] now"); len(r.Leaks) != 0 {
		t.Fatalf("want no leak, got %+v", r)
	}
	benign := &Stream{TextHash: HashText("hello world")}
	if r := Check(benign, "hello world"); r.Altered {
		t.Fatal("unexpected alteration")
	}
	if r := Check(benign, "hello [x] world"); !r.Altered {
		t.Fatal("alteration not detected")
	}
}

func TestSampledDeterministicAndRoughRate(t *testing.T) {
	n, hit := 20000, 0
	for i := 0; i < n; i++ {
		id := "s" + string(rune('a'+i%26)) + itoa(i)
		a, b := Sampled(id, 0.1), Sampled(id, 0.1)
		if a != b {
			t.Fatal("not deterministic")
		}
		if a {
			hit++
		}
	}
	if r := float64(hit) / float64(n); r < 0.08 || r > 0.12 {
		t.Fatalf("rate %.3f, want ~0.1", r)
	}
	if !Sampled("x", 1) || Sampled("x", 0) {
		t.Fatal("edge fractions wrong")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func TestWriterLoadRoundTripAndEmitLog(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(filepath.Join(dir, "gt.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	in := &Stream{StreamID: "s1", Surface: "chat", TextLen: 5, TextHash: HashText("hello"), EventEnds: []int{2, 5},
		Spans: []Span{{Class: "PCI.PAN", Value: "v", Hash: HashValue("v"), Offset: 1, Len: 1}}}
	if err := w.Write(in); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	m, err := Load(filepath.Join(dir, "gt.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if got := m["s1"]; got == nil || got.TextHash != in.TextHash || len(got.Spans) != 1 || got.EventEnds[1] != 5 {
		t.Fatalf("round trip mismatch: %+v", got)
	}

	ew, err := NewEmitWriter(filepath.Join(dir, "emit.csv"))
	if err != nil {
		t.Fatal(err)
	}
	ew.WriteStream("s1", []int64{10, 20, 30}, []int64{11, 22, 33})
	ew.WriteStream("s2", []int64{1}, []int64{2})
	if err := ew.Close(); err != nil {
		t.Fatal(err)
	}
	em, err := LoadEmit(filepath.Join(dir, "emit.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if len(em["s1"]) != 3 || em["s1"][2] != 33 || em["s2"][0] != 2 {
		t.Fatalf("emit round trip mismatch: %+v", em)
	}
}
