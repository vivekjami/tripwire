package gateway

import (
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// frozen is the metric contract of docs/metrics.md.
var frozen = map[string]string{
	"tw_http_requests_total": "counter", "tw_http_request_seconds": "histogram", "tw_inflight_requests": "gauge",
	"tw_shed_total": "counter", "tw_auth_failures_total": "counter", "tw_panics_total": "counter",
	"tw_tls_reload_total": "counter", "tw_registry_reload_total": "counter", "tw_registry_agents": "gauge",
	"tw_upstream_requests_total": "counter", "tw_upstream_seconds": "histogram",
	"tw_streams_active": "gauge", "tw_streams_total": "counter", "tw_stream_events_total": "counter", "tw_stream_bytes_total": "counter",
	"tw_stream_event_added_seconds": "histogram", "tw_stream_first_event_seconds": "histogram",
	"tw_lineage_events_total": "counter", "tw_lineage_dropped_total": "counter", "tw_lineage_committed_total": "counter",
	"tw_lineage_failed_total": "counter", "tw_lineage_queue_depth": "gauge", "tw_lineage_batch_rows": "histogram",
}

func TestMetricNamesAreTheFrozenContract(t *testing.T) {
	r, _ := startAPI(t, mockUpstream(), nil)
	post(t, r, okReq, nil)
	readAll(streamPost(t, r, streamReq))
	resp, err := http.Get(r.admURL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	typeRE := regexp.MustCompile(`(?m)^# TYPE (tw_\w+) (\w+)$`)
	got := map[string]string{}
	for _, m := range typeRE.FindAllStringSubmatch(string(b), -1) {
		got[m[1]] = m[2]
	}
	for name, typ := range frozen {
		if got[name] != typ {
			t.Errorf("%s: type %q in /metrics, contract says %q", name, got[name], typ)
		}
	}
	for name := range got {
		if _, ok := frozen[name]; !ok {
			t.Errorf("%s is exported but not part of the frozen contract: add it to docs/metrics.md and this test, or remove it", name)
		}
	}
	// the documentation lists exactly the same set
	doc, err := os.ReadFile("../../docs/metrics.md")
	if err != nil {
		t.Fatal(err)
	}
	var documented []string
	for _, m := range regexp.MustCompile(`(?m)^\| (tw_\w+) \|`).FindAllStringSubmatch(string(doc), -1) {
		documented = append(documented, m[1])
	}
	var want []string
	for n := range frozen {
		want = append(want, n)
	}
	sort.Strings(documented)
	sort.Strings(want)
	if strings.Join(documented, ",") != strings.Join(want, ",") {
		t.Errorf("docs/metrics.md and the contract differ:\n doc:  %v\n code: %v", documented, want)
	}
	// no metric may carry a high-cardinality or sensitive label
	for _, bad := range []string{`agent=`, `tenant=`, `path=`, `model=`, `key=`, `token=`} {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "tw_") && strings.Contains(line, bad) {
				t.Errorf("metric line carries label %s: %s", bad, line)
			}
		}
	}
}
