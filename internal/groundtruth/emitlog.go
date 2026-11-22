package groundtruth

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// EmitWriter records, for sampled streams, the CLOCK_MONOTONIC nanosecond at
// which each SSE event was handed to the socket by twmock. Records are
// accumulated per stream in memory by the caller and appended with one lock
// acquisition when the stream ends, keeping the emit path lock-free.
//
// Line format (CSV, no header): stream_id,event_idx,sched_ns,emit_ns
type EmitWriter struct {
	mu sync.Mutex
	f  *os.File
	bw *bufio.Writer
}

// NewEmitWriter creates (truncating) an emit log.
func NewEmitWriter(path string) (*EmitWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &EmitWriter{f: f, bw: bufio.NewWriterSize(f, 1<<20)}, nil
}

// WriteStream appends all events of one stream.
func (w *EmitWriter) WriteStream(id string, sched, emit []int64) {
	buf := make([]byte, 0, 64*len(emit))
	for i := range emit {
		buf = append(buf, id...)
		buf = append(buf, ',')
		buf = strconv.AppendInt(buf, int64(i), 10)
		buf = append(buf, ',')
		buf = strconv.AppendInt(buf, sched[i], 10)
		buf = append(buf, ',')
		buf = strconv.AppendInt(buf, emit[i], 10)
		buf = append(buf, '\n')
	}
	w.mu.Lock()
	w.bw.Write(buf)
	w.mu.Unlock()
}

// Close flushes and closes.
func (w *EmitWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.bw.Flush(); err != nil {
		return err
	}
	return w.f.Close()
}

// Flush flushes buffered lines.
func (w *EmitWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.bw.Flush()
}

// LoadEmit reads an emit log into stream_id -> emit_ns by event index.
func LoadEmit(path string) (map[string][]int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := make(map[string][]int64)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for ln := 1; sc.Scan(); ln++ {
		parts := strings.Split(sc.Text(), ",")
		if len(parts) != 4 {
			return nil, fmt.Errorf("%s:%d: want 4 fields, got %d", path, ln, len(parts))
		}
		idx, err1 := strconv.Atoi(parts[1])
		emit, err2 := strconv.ParseInt(parts[3], 10, 64)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("%s:%d: bad number", path, ln)
		}
		s := out[parts[0]]
		for len(s) <= idx {
			s = append(s, 0)
		}
		s[idx] = emit
		out[parts[0]] = s
	}
	return out, sc.Err()
}
