//go:build linux

// Package clock provides a monotonic nanosecond clock whose readings are
// comparable ACROSS processes on the same host. The Go runtime's monotonic
// reading (time.Now) is process-relative and cannot be joined between
// twmock (emit time) and twload (receive time); CLOCK_MONOTONIC can.
package clock

import "golang.org/x/sys/unix"

// Now returns CLOCK_MONOTONIC in nanoseconds.
func Now() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		panic("clock: clock_gettime: " + err.Error())
	}
	return ts.Nano()
}
