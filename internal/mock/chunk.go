package mock

import (
	"fmt"
	"math/rand/v2"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/vivekjami/tripwire/internal/groundtruth"
)

// Piece is the content carried by one SSE event. Normally S holds valid UTF-8.
// When Surr != 0 the piece is a LONE UTF-16 surrogate code unit, which a JSON
// document may legally carry as a \uD83D-style escape; the adversarial chunker
// emits the two halves of an astral character in two different events, which
// is how some providers really behave and the case a streaming JSON decoder
// must carry state across.
type Piece struct {
	S    string
	Surr uint16
}

// Chunk splits text into pieces according to mode. Concatenating the pieces
// (rejoining surrogate halves) always reproduces text exactly.
//
// Modes:
//
//	token        word-ish pieces with a leading space; alphanumeric runs > 4 runes are
//	             cut every 4 (so a PAN arrives as "4111", " 1111", ...: the normal case)
//	per-char     one rune per piece
//	random:p     cut at every rune boundary with probability p
//	boundary     every rune boundary within 1 rune of each injected span; elsewhere 8-24 rune pieces
//	adversarial  boundary with a 8-rune window, plus astral runes split into surrogate halves
func Chunk(text string, spans []groundtruth.Span, mode string, r *rand.Rand) ([]Piece, error) {
	if text == "" {
		return nil, nil
	}
	cut := make([]bool, len(text)+1) // cut[i]: a piece boundary immediately before byte i
	starts := make([]int, 0, len(text))
	for i := range text {
		starts = append(starts, i)
	}

	switch {
	case mode == "" || mode == "token":
		tokenCuts(text, cut)
	case mode == "per-char":
		for _, s := range starts {
			cut[s] = true
		}
	case strings.HasPrefix(mode, "random:"):
		p, err := strconv.ParseFloat(mode[len("random:"):], 64)
		if err != nil || p <= 0 || p > 1 {
			return nil, fmt.Errorf("chunk %q: want random:<p in (0,1]>", mode)
		}
		for _, s := range starts {
			if r.Float64() < p {
				cut[s] = true
			}
		}
	case mode == "boundary", mode == "adversarial":
		win := 1
		if mode == "adversarial" {
			win = 8
		}
		boundaryCuts(text, starts, spans, win, r, cut)
	default:
		return nil, fmt.Errorf("unknown chunk mode %q", mode)
	}

	var out []Piece
	prev := 0
	for i := 1; i <= len(text); i++ {
		if cut[i] || i == len(text) {
			if i > prev {
				out = append(out, Piece{S: text[prev:i]})
			}
			prev = i
		}
	}
	if mode == "adversarial" {
		out = splitSurrogates(out, r)
	}
	return out, nil
}

func tokenCuts(text string, cut []bool) {
	const (
		cSpace = iota
		cAlnum
		cOther
	)
	class := func(r rune) int {
		switch {
		case r == ' ' || r == '\n' || r == '\t':
			return cSpace
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			return cAlnum
		}
		return cOther
	}
	prevClass, runLen := -1, 0
	for i, r := range text {
		c := class(r)
		switch {
		case prevClass == -1:
			runLen = 1
		case prevClass == cSpace:
			// a space leads the next token; stay in the same piece
			runLen = 1
		case c == cSpace, c != prevClass:
			cut[i] = true
			runLen = 1
		case c == cAlnum && runLen >= 4:
			cut[i] = true
			runLen = 1
		default:
			runLen++
		}
		if c == cSpace {
			prevClass = cSpace
		} else {
			prevClass = c
		}
	}
}

func boundaryCuts(text string, starts []int, spans []groundtruth.Span, win int, r *rand.Rand, cut []bool) {
	inWindow := make([]bool, len(starts))
	for _, sp := range spans {
		i0 := sort.SearchInts(starts, sp.Offset)
		i1 := sort.SearchInts(starts, sp.Offset+sp.Len)
		for i := max(0, i0-win); i <= min(len(starts)-1, i1+win); i++ {
			inWindow[i] = true
		}
	}
	since, next := 0, 8+r.IntN(17)
	for i, s := range starts {
		if inWindow[i] {
			cut[s] = true
			since = 0
			next = 8 + r.IntN(17)
			continue
		}
		since++
		if since >= next {
			cut[s] = true
			since = 0
			next = 8 + r.IntN(17)
		}
	}
}

// splitSurrogates splits astral runes into hi/lo surrogate pieces (70% of the time).
func splitSurrogates(in []Piece, r *rand.Rand) []Piece {
	out := make([]Piece, 0, len(in)+4)
	for _, p := range in {
		if !hasAstral(p.S) || r.Float64() > 0.7 {
			out = append(out, p)
			continue
		}
		pre := 0
		for i, ru := range p.S {
			if ru < 0x10000 {
				continue
			}
			if i > pre {
				out = append(out, Piece{S: p.S[pre:i]})
			}
			r1, r2 := surrogates(ru)
			out = append(out, Piece{Surr: r1}, Piece{Surr: r2})
			pre = i + utf8.RuneLen(ru)
		}
		if pre < len(p.S) {
			out = append(out, Piece{S: p.S[pre:]})
		}
	}
	return out
}

func hasAstral(s string) bool {
	for _, r := range s {
		if r >= 0x10000 {
			return true
		}
	}
	return false
}

func surrogates(r rune) (uint16, uint16) {
	r -= 0x10000
	return uint16(0xD800 + (r>>10)&0x3FF), uint16(0xDC00 + r&0x3FF)
}

// JoinPieces reassembles pieces into text (rejoining surrogate halves).
func JoinPieces(ps []Piece) string {
	var units []uint16
	var sb strings.Builder
	flush := func() {
		if len(units) > 0 {
			sb.WriteString(groundtruth.UnitsToString(units))
			units = units[:0]
		}
	}
	for _, p := range ps {
		if p.Surr != 0 {
			units = append(units, p.Surr)
			continue
		}
		flush()
		sb.WriteString(p.S)
	}
	flush()
	return sb.String()
}

// byteLen is the number of decoded bytes this piece completes: a high
// surrogate completes nothing, the matching low surrogate completes the rune.
func (p Piece) byteLen() int {
	switch {
	case p.Surr >= 0xD800 && p.Surr < 0xDC00:
		return 0
	case p.Surr >= 0xDC00:
		return 4
	}
	return len(p.S)
}

// appendJSON appends the JSON string literal for the piece. ascii forces
// \uXXXX escapes for every non-ASCII rune (what Python's json.dumps does by
// default); otherwise non-ASCII is emitted as raw UTF-8.
func (p Piece) appendJSON(dst []byte, ascii bool) []byte {
	dst = append(dst, '"')
	if p.Surr != 0 {
		dst = appendU(dst, p.Surr)
		return append(dst, '"')
	}
	for _, r := range p.S {
		switch {
		case r == '"':
			dst = append(dst, '\\', '"')
		case r == '\\':
			dst = append(dst, '\\', '\\')
		case r == '\n':
			dst = append(dst, '\\', 'n')
		case r == '\r':
			dst = append(dst, '\\', 'r')
		case r == '\t':
			dst = append(dst, '\\', 't')
		case r < 0x20:
			dst = appendU(dst, uint16(r))
		case r < 0x80:
			dst = append(dst, byte(r))
		case ascii && r >= 0x10000:
			a, b := surrogates(r)
			dst = appendU(appendU(dst, a), b)
		case ascii:
			dst = appendU(dst, uint16(r))
		default:
			dst = utf8.AppendRune(dst, r)
		}
	}
	return append(dst, '"')
}

func appendU(dst []byte, u uint16) []byte {
	const hexd = "0123456789abcdef"
	return append(dst, '\\', 'u', hexd[u>>12&0xF], hexd[u>>8&0xF], hexd[u>>4&0xF], hexd[u&0xF])
}
