// Package sse is the incremental Server-Sent Events codec (WP1.4,
// ARCHITECTURE §5.3). The decoder reads into one reused window, yields events
// that point into that window (no per-event allocation), and keeps the exact
// original bytes of every event so unmodified events are forwarded verbatim.
//
// Wire rules implemented (WHATWG SSE): lines end with CRLF, LF or CR; a blank
// line ends an event; a leading UTF-8 BOM is ignored; lines starting with ':'
// are comments; a field is "name: value" (one optional space after the colon);
// repeated data fields are joined with "\n". Anything past the event-size cap
// fails the stream instead of buffering without bound.
package sse

import (
	"bytes"
	"errors"
	"io"
)

// Errors.
var (
	ErrEventTooLarge = errors.New("sse: event exceeds size limit")
	ErrTruncated     = errors.New("sse: stream ended inside an event")
)

// Event is one block of lines ended by a blank line. Slices are valid until the
// next call to Next.
type Event struct {
	Raw     []byte // exact bytes of the block including its terminating blank line
	Data    []byte // joined data fields (nil if the block had none)
	HasData bool
	Type    []byte // "event" field
	ID      []byte // "id" field
}

// Decoder reads events from a stream.
type Decoder struct {
	r       io.Reader
	buf     []byte
	start   int // first byte of the unconsumed window
	end     int // end of valid bytes
	max     int
	bom     bool // BOM check done
	eof     error
	scratch []byte
}

// NewDecoder returns a decoder with a per-event size cap (bytes of Raw).
func NewDecoder(r io.Reader, maxEvent int) *Decoder {
	return &Decoder{r: r, max: maxEvent, buf: make([]byte, 16<<10)}
}

// Reset reuses the decoder (and its buffers) for a new stream.
func (d *Decoder) Reset(r io.Reader) {
	d.r, d.start, d.end, d.bom, d.eof = r, 0, 0, false, nil
}

func (d *Decoder) fill() error {
	if d.eof != nil {
		return d.eof
	}
	if d.start > 0 && d.start == d.end {
		d.start, d.end = 0, 0
	}
	if d.end == len(d.buf) {
		if d.start > 0 { // compact
			n := copy(d.buf, d.buf[d.start:d.end])
			d.start, d.end = 0, n
		}
		if d.end == len(d.buf) {
			grow := len(d.buf)*2 + 4096
			if grow > d.max+4096 {
				grow = d.max + 4096
			}
			if grow <= len(d.buf) {
				return ErrEventTooLarge
			}
			nb := make([]byte, grow)
			copy(nb, d.buf[:d.end])
			d.buf = nb
		}
	}
	n, err := d.r.Read(d.buf[d.end:])
	d.end += n
	if err != nil {
		d.eof = err
		if n > 0 {
			return nil
		}
		return err
	}
	return nil
}

// Next returns the next complete event. At a clean end of stream it returns
// io.EOF; if the stream ends inside an event it returns ErrTruncated (the
// partial event is never delivered).
func (d *Decoder) Next() (Event, error) {
	scan, lineStart := d.start, d.start
	rescanned := false
	for {
		// A BOM is only meaningful at the very first bytes of the stream.
		if !d.bom && d.end > d.start {
			if d.buf[d.start] != 0xEF {
				d.bom = true
			} else if d.end-d.start >= 3 {
				d.bom = true
				if d.buf[d.start+1] == 0xBB && d.buf[d.start+2] == 0xBF {
					d.start += 3
					scan, lineStart = d.start, d.start
				}
			}
		}
		for scan < d.end {
			c := d.buf[scan]
			if c != '\n' && c != '\r' {
				scan++
				continue
			}
			next := scan + 1
			if c == '\r' {
				if next >= d.end && d.eof == nil {
					break // need one more byte to know whether this is CRLF
				}
				if next < d.end && d.buf[next] == '\n' {
					next++
				}
			}
			if scan == lineStart { // blank line
				if lineStart == d.start { // nothing before it: skip stray blank lines
					d.start = next
					scan, lineStart = next, next
					continue
				}
				return d.emit(next), nil
			}
			scan, lineStart = next, next
			if next-d.start > d.max {
				return Event{}, ErrEventTooLarge
			}
		}
		if d.end-d.start > d.max {
			return Event{}, ErrEventTooLarge
		}
		pending := d.end - d.start
		old := d.start
		err := d.fill()
		delta := old - d.start // fill may compact the window
		scan, lineStart = scan-delta, lineStart-delta
		if err != nil {
			if errors.Is(err, io.EOF) {
				if !rescanned && pending > 0 {
					// a trailing CR was waiting for a lookahead byte that will never come: re-scan, now at EOF
					rescanned = true
					continue
				}
				if pending == 0 {
					return Event{}, io.EOF
				}
				return Event{}, ErrTruncated
			}
			return Event{}, err
		}
	}
}

// emit parses the block buf[start:end) and consumes it.
func (d *Decoder) emit(end int) Event {
	raw := d.buf[d.start:end]
	ev := Event{Raw: raw}
	joined := false
	for pos := 0; pos < len(raw); {
		le := pos
		for le < len(raw) && raw[le] != '\n' && raw[le] != '\r' {
			le++
		}
		line := raw[pos:le]
		switch {
		case le >= len(raw):
			pos = le
		case raw[le] == '\r' && le+1 < len(raw) && raw[le+1] == '\n':
			pos = le + 2
		default:
			pos = le + 1
		}
		if len(line) == 0 || line[0] == ':' {
			continue
		}
		name, val := line, []byte(nil)
		if i := bytes.IndexByte(line, ':'); i >= 0 {
			name, val = line[:i], line[i+1:]
			if len(val) > 0 && val[0] == ' ' {
				val = val[1:]
			}
		}
		switch string(name) {
		case "data":
			if !ev.HasData {
				ev.HasData, ev.Data = true, val
			} else {
				if !joined {
					d.scratch = append(d.scratch[:0], ev.Data...)
					joined = true
				}
				d.scratch = append(append(d.scratch, '\n'), val...)
				ev.Data = d.scratch
			}
		case "event":
			ev.Type = val
		case "id":
			ev.ID = val
		}
	}
	d.start = end
	return ev
}

// AppendEvent appends a data event (optionally typed) in canonical form; a
// payload containing newlines becomes multiple data lines.
func AppendEvent(dst []byte, typ string, data []byte) []byte {
	if typ != "" {
		dst = append(append(append(dst, "event: "...), typ...), '\n')
	}
	for {
		i := bytes.IndexByte(data, '\n')
		line := data
		if i >= 0 {
			line = data[:i]
		}
		dst = append(append(append(dst, "data: "...), line...), '\n')
		if i < 0 {
			break
		}
		data = data[i+1:]
	}
	return append(dst, '\n')
}
