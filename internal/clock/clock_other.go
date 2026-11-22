//go:build !linux

// Package clock: non-Linux fallback (development only). Wall-clock readings
// are comparable across processes on one host but are NOT monotonic; the rig
// is Linux, so published numbers never use this path.
package clock

import "time"

// Now returns wall-clock nanoseconds since the Unix epoch.
func Now() int64 { return time.Now().UnixNano() }
