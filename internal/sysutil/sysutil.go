// Package sysutil holds small process-level helpers shared by the commands.
package sysutil

import (
	"syscall"
)

// RaiseNoFile lifts RLIMIT_NOFILE soft limit to the hard limit and returns the
// resulting soft limit. 26 K concurrent streams need > 52 K descriptors across
// both legs, so every load/proxy/mock process calls this at startup.
func RaiseNoFile() (uint64, error) {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0, err
	}
	rl.Cur = rl.Max
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0, err
	}
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0, err
	}
	return uint64(rl.Cur), nil
}

// CPUSeconds returns user+system CPU time consumed by this process so far.
func CPUSeconds() float64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	tv := func(t syscall.Timeval) float64 { return float64(t.Sec) + float64(t.Usec)/1e6 }
	return tv(ru.Utime) + tv(ru.Stime)
}
