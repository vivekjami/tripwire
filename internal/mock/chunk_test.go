package mock

import (
	"strings"
	"testing"

	"github.com/vivekjami/tripwire/internal/gen"
	"github.com/vivekjami/tripwire/internal/groundtruth"
)

var chunkModes = []string{"token", "per-char", "random:0.3", "random:1", "boundary", "adversarial"}

func TestChunkReassembly(t *testing.T) {
	for seed := int64(1); seed <= 60; seed++ {
		r := gen.NewRand(seed)
		vals := []gen.Value{gen.PAN{}.Generate(r), gen.AWSAccessKey{}.Generate(r), gen.Email{}.Generate(r)}
		text, spans := buildText(r, 300, vals)
		for _, sp := range spans {
			if text[sp.Offset:sp.Offset+sp.Len] != sp.Value {
				t.Fatalf("span offset wrong: %q vs %q", text[sp.Offset:sp.Offset+sp.Len], sp.Value)
			}
		}
		if len(spans) != len(vals) {
			t.Fatalf("spans %d != vals %d", len(spans), len(vals))
		}
		for _, mode := range chunkModes {
			ps, err := Chunk(text, spans, mode, gen.NewRand(seed+1000))
			if err != nil {
				t.Fatal(err)
			}
			if got := JoinPieces(ps); got != text {
				t.Fatalf("mode %s seed %d: reassembly mismatch\n got %q\nwant %q", mode, seed, got, text)
			}
			// decoded-byte accounting must add up to the text length
			sum := 0
			for _, p := range ps {
				sum += p.byteLen()
			}
			if sum != len(text) {
				t.Fatalf("mode %s: byteLen sum %d != %d", mode, sum, len(text))
			}
		}
	}
}

func TestTokenModeSplitsPANAcrossEvents(t *testing.T) {
	// The headline case: a PAN must arrive spread over several events.
	ps, err := Chunk("pay 4111 1111 1111 1111 now", []groundtruth.Span{{Offset: 4, Len: 19}}, "token", gen.NewRand(1))
	if err != nil {
		t.Fatal(err)
	}
	var s []string
	for _, p := range ps {
		s = append(s, p.S)
	}
	want := []string{"pay", " 4111", " 1111", " 1111", " 1111", " now"}
	if strings.Join(s, "|") != strings.Join(want, "|") {
		t.Fatalf("pieces %q, want %q", s, want)
	}
}

func TestAdversarialSplitsSurrogates(t *testing.T) {
	text := strings.Repeat("a😀b ", 50)
	ps, err := Chunk(text, nil, "adversarial", gen.NewRand(3))
	if err != nil {
		t.Fatal(err)
	}
	lone := 0
	for _, p := range ps {
		if p.Surr != 0 {
			lone++
		}
	}
	if lone == 0 {
		t.Fatal("expected lone surrogate pieces")
	}
	if JoinPieces(ps) != text {
		t.Fatal("reassembly mismatch")
	}
}

func TestPieceJSONRoundTrip(t *testing.T) {
	for _, ascii := range []bool{false, true} {
		var units []uint16
		in := "he said \"hi\"\\\n\t\x01 é€😀"
		ps, _ := Chunk(in, nil, "per-char", gen.NewRand(1))
		ps = splitSurrogates(ps, gen.NewRand(1))
		for _, p := range ps {
			lit := p.appendJSON(nil, ascii)
			u, err := groundtruth.DecodeJSONString(lit)
			if err != nil {
				t.Fatalf("decode %s: %v", lit, err)
			}
			units = append(units, u...)
			if ascii {
				for _, b := range lit {
					if b >= 0x80 {
						t.Fatalf("ascii mode emitted non-ASCII byte in %q", lit)
					}
				}
			}
		}
		if got := groundtruth.UnitsToString(units); got != in {
			t.Fatalf("ascii=%v: got %q want %q", ascii, got, in)
		}
	}
}

func TestBenignTextHasNoDigitsOrAt(t *testing.T) {
	text, _ := buildText(gen.NewRand(5), 5000, nil)
	if strings.ContainsAny(text, "0123456789@") {
		t.Fatal("benign corpus must not contain digits or '@'")
	}
}

func FuzzChunkReassembly(f *testing.F) {
	f.Add("hello 4111 1111 1111 1111 😀 world", int64(1), uint8(0))
	f.Fuzz(func(t *testing.T, text string, seed int64, m uint8) {
		if !validUTF8(text) {
			return
		}
		mode := chunkModes[int(m)%len(chunkModes)]
		ps, err := Chunk(text, nil, mode, gen.NewRand(seed))
		if err != nil {
			t.Fatal(err)
		}
		if JoinPieces(ps) != text {
			t.Fatalf("mode %s reassembly mismatch for %q", mode, text)
		}
	})
}

func validUTF8(s string) bool {
	for _, r := range s {
		if r == 0xFFFD {
			return false
		}
	}
	return true
}
