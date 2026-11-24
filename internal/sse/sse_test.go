package sse

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/vivekjami/tripwire/internal/testkit"
)

func decodeAll(r io.Reader, max int) (evs []testkit.RefBlock, err error) {
	d := NewDecoder(r, max)
	for {
		ev, e := d.Next()
		if e == io.EOF {
			return evs, nil
		}
		if e != nil {
			return evs, e
		}
		evs = append(evs, testkit.RefBlock{Raw: string(ev.Raw), HasData: ev.HasData, Data: string(ev.Data), Type: string(ev.Type), ID: string(ev.ID)})
	}
}

func TestBasicEvents(t *testing.T) {
	in := "data: {\"a\":1}\n\ndata: [DONE]\n\n"
	evs, err := decodeAll(strings.NewReader(in), 1<<20)
	if err != nil || len(evs) != 2 || evs[0].Data != `{"a":1}` || evs[1].Data != "[DONE]" {
		t.Fatalf("%+v %v", evs, err)
	}
	if evs[0].Raw+evs[1].Raw != in {
		t.Fatalf("Raw bytes must reproduce the stream exactly: %q", evs[0].Raw+evs[1].Raw)
	}
}

func TestLineEndingsCommentsBOMMultiline(t *testing.T) {
	cases := map[string]struct {
		in   string
		want []testkit.RefBlock
	}{
		"CRLF":      {"data: a\r\n\r\ndata: b\r\n\r\n", []testkit.RefBlock{{Raw: "data: a\r\n\r\n", HasData: true, Data: "a"}, {Raw: "data: b\r\n\r\n", HasData: true, Data: "b"}}},
		"CR only":   {"data: a\r\rdata: b\r\r", []testkit.RefBlock{{Raw: "data: a\r\r", HasData: true, Data: "a"}, {Raw: "data: b\r\r", HasData: true, Data: "b"}}},
		"mixed":     {"data: a\r\n\ndata: b\n\r\n", []testkit.RefBlock{{Raw: "data: a\r\n\n", HasData: true, Data: "a"}, {Raw: "data: b\n\r\n", HasData: true, Data: "b"}}},
		"BOM":       {"\xef\xbb\xbfdata: a\n\n", []testkit.RefBlock{{Raw: "data: a\n\n", HasData: true, Data: "a"}}},
		"comment":   {": ping\n\ndata: a\n\n", []testkit.RefBlock{{Raw: ": ping\n\n"}, {Raw: "data: a\n\n", HasData: true, Data: "a"}}},
		"multiline": {"data: a\ndata: b\ndata\ndata: c\n\n", []testkit.RefBlock{{Raw: "data: a\ndata: b\ndata\ndata: c\n\n", HasData: true, Data: "a\nb\n\nc"}}},
		"no space":  {"data:a\n\n", []testkit.RefBlock{{Raw: "data:a\n\n", HasData: true, Data: "a"}}},
		"two space": {"data:  a\n\n", []testkit.RefBlock{{Raw: "data:  a\n\n", HasData: true, Data: " a"}}},
		"fields":    {"event: x\nid: 7\ndata: a\nretry: 1\n\n", []testkit.RefBlock{{Raw: "event: x\nid: 7\ndata: a\nretry: 1\n\n", HasData: true, Data: "a", Type: "x", ID: "7"}}},
		"stray":     {"\n\n\ndata: a\n\n", []testkit.RefBlock{{Raw: "data: a\n\n", HasData: true, Data: "a"}}},
	}
	for name, c := range cases {
		got, err := decodeAll(strings.NewReader(c.in), 1<<20)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: %d events, want %d: %+v", name, len(got), len(c.want), got)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s[%d]: got %+v want %+v", name, i, got[i], c.want[i])
			}
		}
	}
}

func TestEverySegmentationGivesTheSameEvents(t *testing.T) {
	in := "\xef\xbb\xbf: hi\r\ndata: {\"a\":\"é😀\"}\r\n\r\ndata: x\rdata: y\r\rdata: [DONE]\n\n"
	want, _ := decodeAll(strings.NewReader(in), 1<<20)
	if len(want) != 3 {
		t.Fatalf("fixture: %d", len(want))
	}
	readers := map[string]func() io.Reader{
		"one byte":     func() io.Reader { return iotest.OneByteReader(strings.NewReader(in)) },
		"half":         func() io.Reader { return iotest.HalfReader(strings.NewReader(in)) },
		"data err eof": func() io.Reader { return iotest.DataErrReader(strings.NewReader(in)) },
	}
	for name, mk := range readers {
		got, err := decodeAll(mk(), 1<<20)
		if err != nil || len(got) != len(want) {
			t.Fatalf("%s: %v %d", name, err, len(got))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s[%d]: %+v vs %+v", name, i, got[i], want[i])
			}
		}
	}
	for cut := 0; cut <= len(in); cut++ {
		r := io.MultiReader(strings.NewReader(in[:cut]), strings.NewReader(in[cut:]))
		got, err := decodeAll(r, 1<<20)
		if err != nil || len(got) != len(want) {
			t.Fatalf("cut %d: %v %d", cut, err, len(got))
		}
	}
}

func TestLimitsAndTruncation(t *testing.T) {
	big := "data: " + strings.Repeat("a", 5000) + "\n\n"
	if _, err := decodeAll(strings.NewReader(big), 1000); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("oversize: %v", err)
	}
	if _, err := decodeAll(strings.NewReader(big), 1<<20); err != nil {
		t.Fatalf("under cap: %v", err)
	}
	// no terminator at all, ever: must stop at the cap, not buffer forever
	if _, err := decodeAll(io.LimitReader(zeros{}, 10<<20), 64<<10); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("unbounded line: %v", err)
	}
	evs, err := decodeAll(strings.NewReader("data: a\n\ndata: partial"), 1<<20)
	if !errors.Is(err, ErrTruncated) || len(evs) != 1 {
		t.Fatalf("truncated stream: %v %d", err, len(evs))
	}
	if _, err := decodeAll(strings.NewReader(""), 1<<20); err != nil {
		t.Fatalf("empty stream: %v", err)
	}
	boom := errors.New("boom")
	if _, err := decodeAll(io.MultiReader(strings.NewReader("data: a\n\n"), iotest.ErrReader(boom)), 1<<20); !errors.Is(err, boom) {
		t.Fatalf("read error must surface: %v", err)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func TestAppendEvent(t *testing.T) {
	got := string(AppendEvent(nil, "", []byte("x\ny")))
	if got != "data: x\ndata: y\n\n" {
		t.Fatalf("%q", got)
	}
	evs, _ := decodeAll(strings.NewReader(got), 1<<20)
	if evs[0].Data != "x\ny" {
		t.Fatal("round trip")
	}
	if got := string(AppendEvent(nil, "error", []byte("{}"))); got != "event: error\ndata: {}\n\n" {
		t.Fatalf("%q", got)
	}
}

func TestSteadyStateDoesNotAllocate(t *testing.T) {
	ev := []byte("data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n")
	stream := bytes.Repeat(ev, 2000)
	r := bytes.NewReader(stream)
	d := NewDecoder(r, 1<<20)
	for i := 0; i < 100; i++ { // warm up
		if _, err := d.Next(); err != nil {
			t.Fatal(err)
		}
	}
	n := testing.AllocsPerRun(1000, func() { _, _ = d.Next() })
	if n != 0 {
		t.Fatalf("Next allocates %.2f per event on the steady-state path", n)
	}
}

// Differential fuzz: the optimized incremental decoder, fed through arbitrary TCP
// segmentation, must agree with the slow reference parser on every stream.
func FuzzSSEDecoder(f *testing.F) {
	for _, s := range []string{
		"data: a\n\ndata: [DONE]\n\n", "data: a\r\n\r\n", ": c\n\ndata: x\ndata: y\n\n", "\xef\xbb\xbfdata: a\r\r",
		"event: e\nid: 1\ndata: z\n\n", "data\n\n", "data:\n\n", "\n\n\ndata: a\n\n", "data: a\rdata: b\r\n\n", "data: a\n",
	} {
		f.Add([]byte(s), uint8(1), uint8(3))
	}
	f.Fuzz(func(t *testing.T, in []byte, c1, c2 uint8) {
		want, truncated := testkit.RefParseSSE(string(in))
		segs := segment(in, int(c1), int(c2))
		got, err := decodeAll(segs, 1<<20)
		if truncated {
			if !errors.Is(err, ErrTruncated) {
				t.Fatalf("reference says the stream is truncated; decoder error=%v\nin=%q", err, in)
			}
		} else if err != nil {
			t.Fatalf("unexpected error %v\nin=%q", err, in)
		}
		if len(got) != len(want) {
			t.Fatalf("event count %d vs reference %d\nin=%q\n got=%+v\nwant=%+v", len(got), len(want), in, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("event %d differs\nin=%q\n got=%+v\nwant=%+v", i, in, got[i], want[i])
			}
		}
	})
}

// segment splits in at up to two points and delivers the parts as separate reads.
func segment(in []byte, a, b int) io.Reader {
	if len(in) == 0 {
		return bytes.NewReader(in)
	}
	i, j := a%(len(in)+1), b%(len(in)+1)
	if i > j {
		i, j = j, i
	}
	return io.MultiReader(bytes.NewReader(in[:i]), bytes.NewReader(in[i:j]), bytes.NewReader(in[j:]))
}

func BenchmarkDecoder(b *testing.B) {
	ev := []byte("data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"}}]}\n\n")
	stream := bytes.Repeat(ev, 10000)
	b.SetBytes(int64(len(ev)))
	b.ReportAllocs()
	d := NewDecoder(bytes.NewReader(stream), 1<<20)
	for i := 0; i < b.N; i++ {
		if _, err := d.Next(); err != nil {
			d.Reset(bytes.NewReader(stream))
		}
	}
}

// HasEvent must agree with Next: true exactly when Next can return an event
// without reading more input.
type noMoreReads struct{ reads int }

func (r *noMoreReads) Read([]byte) (int, error) { r.reads++; return 0, errors.New("must not read") }

func FuzzHasEvent(f *testing.F) {
	for _, s := range []string{"data: a\n\n", "data: a\n", "\n\ndata: a\n\n", "data: a\r\n\r\n", "data: a\r\r", "data: a\r", ": c\n\n", "data: a\n\ndata: b", ""} {
		f.Add([]byte(s), uint8(0))
	}
	f.Fuzz(func(t *testing.T, in []byte, cut uint8) {
		if len(in) > 0 && in[0] == 0xEF { // BOM classification is Next's job; HasEvent is defined after it
			return
		}
		// Deliver a prefix as already-buffered bytes, then fail any further read.
		n := 0
		if len(in) > 0 {
			n = int(cut) % (len(in) + 1)
		}
		d := NewDecoder(io.MultiReader(bytes.NewReader(in[:n]), &noMoreReads{}), 1<<20)
		d.bom = true
		for d.fillOnce() {
		}
		has := d.HasEvent()
		_, err := d.Next()
		if has != (err == nil) {
			t.Fatalf("HasEvent=%v but Next err=%v for %q", has, err, in[:n])
		}
	})
}
