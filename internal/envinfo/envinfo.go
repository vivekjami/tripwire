// Package envinfo captures the machine and build environment into env.json,
// stored beside every benchmark result so a number can always be traced to the
// hardware, kernel settings and commit that produced it.
package envinfo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
)

// Env is the recorded environment. It deliberately omits the hostname and
// scrubs home-directory paths: result directories are committed.
type Env struct {
	Captured   string            `json:"captured_utc"`
	Kernel     string            `json:"kernel"`
	OS         string            `json:"os"`
	Virt       string            `json:"virtualization,omitempty"`
	CPUModel   string            `json:"cpu_model"`
	CPUs       int               `json:"cpus"`
	GOMAXPROCS int               `json:"gomaxprocs"`
	MemTotalKB int64             `json:"mem_total_kb,omitempty"`
	Governor   string            `json:"cpu_governor"`
	THP        string            `json:"transparent_hugepage"`
	NoFile     uint64            `json:"rlimit_nofile"`
	Sysctls    map[string]string `json:"sysctls"`
	NICs       []string          `json:"nics,omitempty"`
	GoVersion  string            `json:"go_version"`
	GitSHA     string            `json:"git_sha"`
	GitDirty   bool              `json:"git_dirty"`
	Args       []string          `json:"args"`
	Notes      []string          `json:"notes,omitempty"`
}

var sysctlPaths = []string{
	"net/core/somaxconn", "net/ipv4/tcp_max_syn_backlog", "net/ipv4/ip_local_port_range",
	"net/ipv4/tcp_tw_reuse", "net/ipv4/tcp_fin_timeout", "fs/nr_open", "fs/file-max",
	"net/core/rmem_max", "net/core/wmem_max", "net/ipv4/tcp_rmem", "net/ipv4/tcp_wmem",
}

func read(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Capture records the current environment. It never fails: unreadable items
// are left empty and listed in Notes so a missing field is visible, not silent.
func Capture() *Env {
	e := &Env{
		Captured:   time.Now().UTC().Format(time.RFC3339),
		CPUs:       runtime.NumCPU(),
		GOMAXPROCS: runtime.GOMAXPROCS(0),
		GoVersion:  runtime.Version(),
		Sysctls:    map[string]string{},
		Args:       scrubAll(os.Args),
	}
	e.Kernel = read("/proc/version")
	if strings.Contains(strings.ToLower(e.Kernel), "microsoft") {
		e.Virt = "WSL2 (shape-only: NOT valid for published numbers)"
	}
	for _, l := range strings.Split(read("/etc/os-release"), "\n") {
		if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
			e.OS = strings.Trim(v, `"`)
		}
	}
	for _, l := range strings.Split(read("/proc/cpuinfo"), "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "model name" {
			e.CPUModel = strings.TrimSpace(v)
			break
		}
	}
	for _, l := range strings.Split(read("/proc/meminfo"), "\n") {
		if strings.HasPrefix(l, "MemTotal:") {
			var kb int64
			f := strings.Fields(l)
			if len(f) >= 2 {
				for _, c := range f[1] {
					kb = kb*10 + int64(c-'0')
				}
			}
			e.MemTotalKB = kb
		}
	}
	e.Governor = read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
	if e.Governor == "" {
		e.Notes = append(e.Notes, "cpu governor not readable (virtualized or no cpufreq)")
	}
	e.THP = read("/sys/kernel/mm/transparent_hugepage/enabled")
	for _, p := range sysctlPaths {
		if v := read(filepath.Join("/proc/sys", p)); v != "" {
			e.Sysctls[strings.ReplaceAll(p, "/", ".")] = v
		}
	}
	if ents, err := os.ReadDir("/sys/class/net"); err == nil {
		for _, n := range ents {
			e.NICs = append(e.NICs, n.Name())
		}
	}
	var rl syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl) == nil {
		e.NoFile = rl.Cur
	}
	e.GitSHA, e.GitDirty = gitInfo()
	return e
}

// gitInfo returns the commit and whether tracked files differ from it. "Dirty"
// deliberately ignores UNTRACKED files (new results/notes do not change the code
// that produced a result); the Go build stamp's vcs.modified counts them, so git
// is asked directly and the build info is only a fallback (e.g. in a container).
func gitInfo() (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output(); err == nil {
		st, _ := exec.CommandContext(ctx, "git", "status", "--porcelain", "--untracked-files=no").Output()
		return strings.TrimSpace(string(out)), len(strings.TrimSpace(string(st))) > 0
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		var sha string
		var dirty bool
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				sha = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
		if sha != "" {
			return sha, dirty
		}
	}
	return "unknown", false
}

// ScrubHome replaces the user's home directory prefix with "~" so result files
// that get committed do not embed a username or local directory layout.
func ScrubHome(s string) string {
	if h, err := os.UserHomeDir(); err == nil && h != "" && h != "/" {
		return strings.ReplaceAll(s, h, "~")
	}
	return s
}

func scrubAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = ScrubHome(s)
	}
	return out
}
