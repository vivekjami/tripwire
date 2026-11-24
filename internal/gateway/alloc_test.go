//go:build !race

// Allocation counts are meaningless under the race detector (it disables sync.Pool reuse),
// so this test only builds without -race. CI runs it in the normal test job.

package gateway

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

// End-to-end allocation measurement of the streaming path. The upstream
// writes pre-built events and the client is a raw socket that just counts
// bytes, so the allocations measured are the gateway's own (decode, scan,
// forward, flush, metrics) plus net/http's per-write machinery on both of its
// sockets.
func TestStreamPassthroughAllocsPerEvent(t *testing.T) {
	if testing.Short() {
		t.Skip("allocation measurement")
	}
	const events = 40_000
	ev := []byte("data: " + chunkJSON(0, "hello world token") + "\n\n")
	var all bytes.Buffer
	for i := 0; i < events; i++ {
		all.Write(ev)
	}
	all.WriteString("data: [DONE]\n\n")
	payload := all.Bytes()

	up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fl := w.(http.Flusher)
		// One event per write+flush, like a real provider. (Writes of 256+ bytes make net/http's
		// chunk writer box the length: an allocation in the *test upstream*, not in the gateway.)
		step := len(ev)
		for off := 0; off < len(payload); off += step {
			end := off + step
			if end > len(payload) {
				end = len(payload)
			}
			w.Write(payload[off:end])
			fl.Flush()
		}
	})
	r, _ := startAPI(t, up, nil)
	readUntilDone := func() {
		c, err := net.Dial("tcp", strings.TrimPrefix(r.dataURL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintf(c, "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", r.key, len(streamReq), streamReq)
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, _ = io.Copy(io.Discard, c) // Connection: close => EOF after the response
	}
	readUntilDone() // warm pools, connections, metrics children
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	readUntilDone()
	runtime.ReadMemStats(&m1)
	perEvent := float64(m1.Mallocs-m0.Mallocs) / events
	t.Logf("allocations per streamed event (whole process, gateway + the two net/http sockets): %.3f", perEvent)
	// This end-to-end number includes net/http's own allocations: on HTTP/1.1 its chunked
	// writer boxes the chunk length for every flush of 256+ bytes (at most one allocation per
	// flush, so at most ~1 per event, and fewer when events are coalesced). The gateway's own
	// per-event path is held to zero in TestPumpPerEventPathDoesNotAllocate; here we only
	// guard against a regression to something worse than the standard library's floor.
	if perEvent > 1.0 {
		t.Fatalf("%.3f allocs/event: more than one allocation per event end to end", perEvent)
	}
}
