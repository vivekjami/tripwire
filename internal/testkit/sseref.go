// Package testkit holds slow, obviously-correct reference implementations used
// as differential-fuzz oracles for the optimized parsers.
package testkit

import "strings"

// RefBlock is one SSE block as a reference parser sees it.
type RefBlock struct {
	Raw     string
	HasData bool
	Data    string
	Type    string
	ID      string
}

// RefParseSSE parses a complete SSE byte stream, character by character, with
// no cleverness. Rules mirror internal/sse: CRLF/LF/CR terminators, a leading
// BOM is skipped, a blank line ends a block, stray leading blank lines are
// skipped, a trailing partial block is dropped (and reported via truncated).
func RefParseSSE(in string) (blocks []RefBlock, truncated bool) {
	in = strings.TrimPrefix(in, "\xef\xbb\xbf")
	var lines []string // lines of the current block, without terminators
	var raw strings.Builder
	var cur strings.Builder
	i := 0
	flush := func() {
		b := RefBlock{Raw: raw.String()}
		var data []string
		for _, ln := range lines {
			if ln == "" || ln[0] == ':' {
				continue
			}
			name, val, found := strings.Cut(ln, ":")
			if found {
				val = strings.TrimPrefix(val, " ")
			}
			switch name {
			case "data":
				b.HasData = true
				data = append(data, val)
			case "event":
				b.Type = val
			case "id":
				b.ID = val
			}
		}
		b.Data = strings.Join(data, "\n")
		blocks = append(blocks, b)
		lines = lines[:0]
		raw.Reset()
	}
	for i < len(in) {
		c := in[i]
		if c != '\n' && c != '\r' {
			cur.WriteByte(c)
			raw.WriteByte(c)
			i++
			continue
		}
		term := string(c)
		if c == '\r' && i+1 < len(in) && in[i+1] == '\n' {
			term = "\r\n"
		}
		i += len(term)
		if cur.Len() == 0 { // blank line
			if len(lines) == 0 { // stray blank line before any content
				continue
			}
			raw.WriteString(term)
			flush()
			continue
		}
		lines = append(lines, cur.String())
		cur.Reset()
		raw.WriteString(term)
	}
	truncated = cur.Len() > 0 || len(lines) > 0
	return blocks, truncated
}
