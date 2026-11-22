// Package groundtruth is the contract between twmock (which injects known
// fake sensitive values and records where) and twload/tweval (which check that
// no clear bytes of those values reach the client). It also carries the
// per-event emit-timestamp log used for the latency join.
package groundtruth

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"
)

// Span is one injected value inside a stream's decoded text.
type Span struct {
	Class  string `json:"class"`
	Value  string `json:"value"` // FAKE value, in clear (test data only)
	Norm   string `json:"norm"`
	Hash   string `json:"hash"`   // sha256(value)[:16] hex; for logs that must not print the value
	Offset int    `json:"offset"` // byte offset in the decoded text
	Len    int    `json:"len"`
}

// Stream is the ground truth for one response stream.
type Stream struct {
	StreamID  string `json:"stream_id"`
	Surface   string `json:"surface"`
	Chunking  string `json:"chunking"`
	Seed      int64  `json:"seed"`
	Fault     string `json:"fault,omitempty"`
	TextLen   int    `json:"text_len"`
	TextHash  string `json:"text_hash"`  // sha256 of the full decoded text (UTF-8)
	EventEnds []int  `json:"event_ends"` // cumulative decoded-byte offset after each content event
	Spans     []Span `json:"spans,omitempty"`
}

// HashValue returns the short hash used in Span.Hash.
func HashValue(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:8])
}

// HashText returns the full-text hash used in Stream.TextHash.
func HashText(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Sampled deterministically decides whether a stream is in the sampled set
// (emit-timestamp log and per-event checks). twmock and twload both call it
// with the same fraction, so neither has to tell the other.
func Sampled(streamID string, frac float64) bool {
	if frac >= 1 {
		return true
	}
	if frac <= 0 {
		return false
	}
	h := fnv.New64a()
	h.Write([]byte(streamID))
	return float64(h.Sum64()>>11)/float64(1<<53) < frac
}

// Writer appends Stream records as JSON lines.
type Writer struct {
	mu sync.Mutex
	f  *os.File
	bw *bufio.Writer
}

// NewWriter creates (truncating) a ground-truth log.
func NewWriter(path string) (*Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &Writer{f: f, bw: bufio.NewWriterSize(f, 256<<10)}, nil
}

// Write appends one record.
func (w *Writer) Write(s *Stream) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bw.Write(b)
	return w.bw.WriteByte('\n')
}

// Flush flushes buffered records to disk.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.bw.Flush()
}

// Close flushes and closes the log.
func (w *Writer) Close() error {
	if err := w.Flush(); err != nil {
		return err
	}
	return w.f.Close()
}

// Load reads a ground-truth log into a map keyed by stream id.
func Load(path string) (map[string]*Stream, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := make(map[string]*Stream)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for ln := 1; sc.Scan(); ln++ {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var s Stream
		if err := json.Unmarshal(sc.Bytes(), &s); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, ln, err)
		}
		out[s.StreamID] = &s
	}
	return out, sc.Err()
}

// Leak describes one injected value whose clear bytes reached the client.
type Leak struct {
	Class string `json:"class"`
	Hash  string `json:"hash"`
}

// Result is the outcome of checking one stream.
type Result struct {
	Leaks   []Leak
	Altered bool // benign text (no injected spans) differs from the generated text
}

// Check compares client-visible text with the stream's ground truth.
//
// A span "leaks" if its value appears verbatim in clientText, or (when the
// normalized form differs, e.g. a PAN rendered with separators) if the
// normalized digits appear verbatim. Partial-span leakage (a masked last-4 is
// policy-legal, but a 10-digit prefix is not) is refined in Phase 2/3 when the
// strict-tier definitions exist; Phase 0 pins the verbatim definition.
func Check(gt *Stream, clientText string) Result {
	var r Result
	for _, sp := range gt.Spans {
		if sp.Value != "" && strings.Contains(clientText, sp.Value) {
			r.Leaks = append(r.Leaks, Leak{Class: sp.Class, Hash: sp.Hash})
			continue
		}
		if sp.Norm != "" && sp.Norm != sp.Value && strings.Contains(clientText, sp.Norm) {
			r.Leaks = append(r.Leaks, Leak{Class: sp.Class, Hash: sp.Hash})
		}
	}
	if len(gt.Spans) == 0 && gt.TextHash != "" && HashText(clientText) != gt.TextHash {
		r.Altered = true
	}
	return r
}

// DecodeJSONString decodes a JSON string literal (including the quotes) into
// UTF-16 code units, PRESERVING lone surrogates. encoding/json would replace a
// lone surrogate escape with U+FFFD, which is exactly the case (an emoji split
// across two SSE events as \ud83d / \ude00) the adversarial chunker produces.
func DecodeJSONString(raw []byte) ([]uint16, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, fmt.Errorf("not a JSON string literal")
	}
	b := raw[1 : len(raw)-1]
	out := make([]uint16, 0, len(b))
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == '\\':
			if i+1 >= len(b) {
				return nil, fmt.Errorf("dangling backslash")
			}
			switch b[i+1] {
			case '"', '\\', '/':
				out = append(out, uint16(b[i+1]))
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				if i+6 > len(b) {
					return nil, fmt.Errorf("short \\u escape")
				}
				var v uint16
				for _, h := range b[i+2 : i+6] {
					d, ok := hexVal(h)
					if !ok {
						return nil, fmt.Errorf("bad hex in \\u escape")
					}
					v = v<<4 | uint16(d)
				}
				out = append(out, v)
				i += 6
				continue
			default:
				return nil, fmt.Errorf("bad escape \\%c", b[i+1])
			}
			i += 2
		case c < 0x80:
			out = append(out, uint16(c))
			i++
		default:
			r, n := decodeRune(b[i:])
			if r < 0 {
				return nil, fmt.Errorf("invalid UTF-8")
			}
			if r >= 0x10000 {
				a, bb := utf16.EncodeRune(rune(r))
				out = append(out, uint16(a), uint16(bb))
			} else {
				out = append(out, uint16(r))
			}
			i += n
		}
	}
	return out, nil
}

// UnitsToString converts accumulated UTF-16 units to a Go string. Surrogate
// halves that were split across events are rejoined by this step; unpaired
// ones become U+FFFD.
func UnitsToString(u []uint16) string { return string(utf16.Decode(u)) }

func hexVal(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}

func decodeRune(b []byte) (int, int) {
	r, n := utf8.DecodeRune(b)
	if r == utf8.RuneError && n <= 1 {
		return -1, 0
	}
	return int(r), n
}
