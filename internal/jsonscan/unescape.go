package jsonscan

import (
	"errors"
	"unicode/utf8"
)

// Unescaper decodes the body of a JSON string (the bytes between the quotes)
// incrementally. State survives between Feed calls, so it handles escapes,
// UTF-8 sequences and surrogate pairs that are split across calls, including a
// \uD83D at the end of one stream event and its \uDE00 at the start of the next
// (WP1.5 "resumable JSON-string-escape decoder").
//
// Output policy: a surrogate that never finds its partner decodes to U+FFFD.
type Unescaper struct {
	state    uint8
	uDigits  uint8
	uVal     rune
	pendHigh rune // a high surrogate waiting for its low half (0 = none)
	utf      [4]byte
	utfN     uint8
	utfNeed  uint8
}

const (
	stNormal uint8 = iota
	stEsc
	stU
	stUTF
)

// ErrBadString is returned for an invalid escape or invalid UTF-8.
var ErrBadString = errors.New("jsonscan: invalid string content")

// Reset clears all carried state.
func (u *Unescaper) Reset() { *u = Unescaper{} }

// Pending reports whether the decoder holds undecided input (a half escape, a
// partial UTF-8 sequence or an unpaired high surrogate).
func (u *Unescaper) Pending() bool { return u.state != stNormal || u.pendHigh != 0 }

func (u *Unescaper) flushHigh(dst []byte) []byte {
	if u.pendHigh != 0 {
		dst = utf8.AppendRune(dst, utf8.RuneError)
		u.pendHigh = 0
	}
	return dst
}

// Feed appends the decoded form of raw to dst.
func (u *Unescaper) Feed(dst, raw []byte) ([]byte, error) {
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch u.state {
		case stNormal:
			switch {
			case c == '\\':
				u.state = stEsc
			case c < utf8.RuneSelf:
				dst = u.flushHigh(dst)
				dst = append(dst, c)
			default:
				need := uint8(0)
				switch {
				case c&0xE0 == 0xC0:
					need = 2
				case c&0xF0 == 0xE0:
					need = 3
				case c&0xF8 == 0xF0:
					need = 4
				default:
					return dst, ErrBadString
				}
				u.utf[0], u.utfN, u.utfNeed, u.state = c, 1, need, stUTF
			}
		case stUTF:
			u.utf[u.utfN] = c
			u.utfN++
			if u.utfN == u.utfNeed {
				r, n := utf8.DecodeRune(u.utf[:u.utfN])
				if r == utf8.RuneError && n <= 1 {
					return dst, ErrBadString
				}
				dst = u.flushHigh(dst)
				dst = append(dst, u.utf[:u.utfN]...)
				u.state = stNormal
			}
		case stEsc:
			var out byte
			switch c {
			case '"', '\\', '/':
				out = c
			case 'b':
				out = '\b'
			case 'f':
				out = '\f'
			case 'n':
				out = '\n'
			case 'r':
				out = '\r'
			case 't':
				out = '\t'
			case 'u':
				u.state, u.uDigits, u.uVal = stU, 0, 0
				continue
			default:
				return dst, ErrBadString
			}
			dst = u.flushHigh(dst)
			dst = append(dst, out)
			u.state = stNormal
		case stU:
			var d rune
			switch {
			case c >= '0' && c <= '9':
				d = rune(c - '0')
			case c >= 'a' && c <= 'f':
				d = rune(c-'a') + 10
			case c >= 'A' && c <= 'F':
				d = rune(c-'A') + 10
			default:
				return dst, ErrBadString
			}
			u.uVal = u.uVal<<4 | d
			u.uDigits++
			if u.uDigits < 4 {
				continue
			}
			u.state = stNormal
			r := u.uVal
			switch {
			case r >= 0xD800 && r <= 0xDBFF:
				dst = u.flushHigh(dst)
				u.pendHigh = r
			case r >= 0xDC00 && r <= 0xDFFF:
				if u.pendHigh != 0 {
					dst = utf8.AppendRune(dst, 0x10000+(u.pendHigh-0xD800)<<10+(r-0xDC00))
					u.pendHigh = 0
				} else {
					dst = utf8.AppendRune(dst, utf8.RuneError)
				}
			default:
				dst = u.flushHigh(dst)
				dst = utf8.AppendRune(dst, r)
			}
		}
	}
	return dst, nil
}

// Flush ends the string: a pending half escape or partial UTF-8 sequence is an
// error; an unpaired high surrogate becomes U+FFFD.
func (u *Unescaper) Flush(dst []byte) ([]byte, error) {
	if u.state != stNormal {
		u.Reset()
		return dst, ErrBadString
	}
	dst = u.flushHigh(dst)
	return dst, nil
}

// DecodeMap decodes a complete string body, recording for every decoded byte the
// raw offset of the character that produced it. offs gets len(decoded)+1
// entries (the last is len(raw)). The body must be valid (it passed the scanner,
// lone surrogates allowed): invalid input yields ErrBadString.
func DecodeMap(dst []byte, offs []int32, raw []byte) ([]byte, []int32, error) {
	var u Unescaper
	// Decode character by character so every produced byte can be attributed.
	i := 0
	for i < len(raw) {
		j := i + 1
		switch {
		case raw[i] == '\\' && i+1 < len(raw) && raw[i+1] == 'u':
			j = i + 6
			if j <= len(raw) && isHighEscape(raw[i:j]) && j+6 <= len(raw) && raw[j] == '\\' && raw[j+1] == 'u' {
				j += 6 // surrogate pair is one character
			}
		case raw[i] == '\\':
			j = i + 2
		case raw[i] >= utf8.RuneSelf:
			_, n := utf8.DecodeRune(raw[i:])
			j = i + n
		}
		if j > len(raw) {
			return dst, offs, ErrBadString
		}
		before := len(dst)
		var err error
		dst, err = u.Feed(dst, raw[i:j])
		if err != nil {
			return dst, offs, err
		}
		if u.Pending() { // a lone high surrogate: decide now (the next character is not its pair)
			if dst, err = u.Flush(dst); err != nil {
				return dst, offs, err
			}
		}
		for k := before; k < len(dst); k++ {
			offs = append(offs, int32(i))
		}
		i = j
	}
	return dst, append(offs, int32(len(raw))), nil
}

func isHighEscape(e []byte) bool {
	r, ok := hex4(e[2:])
	return ok && r >= 0xD800 && r <= 0xDBFF
}

// RawRange maps a decoded byte range [a, b) to the raw byte range covering the
// whole characters it touches. offs comes from DecodeMap.
func RawRange(offs []int32, a, b int) (start, end int) {
	n := len(offs) - 1 // decoded length
	if a >= n {
		return int(offs[n]), int(offs[n])
	}
	start = int(offs[a])
	if b <= a {
		return start, start
	}
	last := int(offs[b-1])
	j := b
	for j < n && int(offs[j]) == last {
		j++
	}
	return start, int(offs[j])
}

// Edit replaces doc[Start:End] with Repl.
type Edit struct {
	Start, End int
	Repl       []byte
}

// ErrBadEdits means edits were unsorted, overlapping or out of range.
var ErrBadEdits = errors.New("jsonscan: invalid edit list")

// Splice returns doc with the edits applied, appended to dst. Bytes outside the
// edits are copied untouched, so a rewritten event is the original event plus
// the replacement (ADR-04, ADR-27).
func Splice(dst, doc []byte, edits []Edit) ([]byte, error) {
	pos := 0
	for _, e := range edits {
		if e.Start < pos || e.End < e.Start || e.End > len(doc) {
			return dst, ErrBadEdits
		}
		dst = append(dst, doc[pos:e.Start]...)
		dst = append(dst, e.Repl...)
		pos = e.End
	}
	return append(dst, doc[pos:]...), nil
}

const hexDigits = "0123456789abcdef"

// AppendEscaped appends text as a JSON string body (no quotes). text must be
// valid UTF-8; invalid bytes become U+FFFD.
func AppendEscaped(dst, text []byte) []byte {
	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case c == '"' || c == '\\':
			dst = append(dst, '\\', c)
		case c == '\n':
			dst = append(dst, '\\', 'n')
		case c == '\r':
			dst = append(dst, '\\', 'r')
		case c == '\t':
			dst = append(dst, '\\', 't')
		case c < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xF])
		case c < utf8.RuneSelf:
			dst = append(dst, c)
		default:
			r, n := utf8.DecodeRune(text[i:])
			if r == utf8.RuneError && n == 1 {
				dst = append(dst, "\xef\xbf\xbd"...)
			} else {
				dst = append(dst, text[i:i+n]...)
			}
			i += n
			continue
		}
		i++
	}
	return dst
}
