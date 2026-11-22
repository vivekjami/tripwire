package envinfo

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestCaptureFillsTheFieldsThatMatter(t *testing.T) {
	e := Capture()
	if e.GoVersion != runtime.Version() || e.CPUs != runtime.NumCPU() || e.GOMAXPROCS < 1 {
		t.Fatalf("runtime fields wrong: %+v", e)
	}
	if e.Kernel == "" || e.CPUModel == "" || e.NoFile == 0 {
		t.Fatalf("host fields missing: kernel=%q cpu=%q nofile=%d", e.Kernel, e.CPUModel, e.NoFile)
	}
	if e.GitSHA == "" {
		t.Fatal("git sha must never be empty (use \"unknown\" explicitly)")
	}
	if len(e.Sysctls) == 0 || e.Sysctls["net.core.somaxconn"] == "" {
		t.Fatalf("sysctls not captured: %v", e.Sysctls)
	}
	if strings.Contains(strings.ToLower(e.Kernel), "microsoft") && !strings.Contains(e.Virt, "NOT valid for published numbers") {
		t.Fatal("WSL2 must be flagged as invalid for published numbers")
	}
	if _, err := json.Marshal(e); err != nil {
		t.Fatal(err)
	}
}

func TestNoHostnameOrHomePathsInEnv(t *testing.T) {
	b, _ := json.Marshal(Capture())
	if h, _ := os.Hostname(); h != "" && strings.Contains(string(b), h) {
		t.Fatalf("env.json must not contain the hostname %q", h)
	}
	if home, _ := os.UserHomeDir(); home != "" && home != "/" && strings.Contains(string(b), home) {
		t.Fatalf("env.json must not contain the home directory %q", home)
	}
	if got := ScrubHome("/x"); got != "/x" {
		t.Fatalf("scrub changed an unrelated path: %q", got)
	}
}
