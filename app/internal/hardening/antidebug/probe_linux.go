//go:build linux

package antidebug

import (
	"bytes"
	"os"
)

func init() { Probe = probeLinux }

// probeLinux reads /proc/self/status and inspects the TracerPid line.
// A non-zero TracerPid indicates ptrace-attach (gdb, strace, perf...).
//
// We deliberately do NOT call ptrace(PTRACE_TRACEME) here even though
// the design doc lists it as an option: TRACEME also interferes with
// the Go runtime's own signal handling and makes the binary fail to
// run under perf/strace even for legitimate debugging during dev.
// Re-enable it under a stricter build tag if the threat model
// demands it.
func probeLinux() string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		// procfs absent => nothing we can prove. Don't false-positive.
		return ""
	}
	idx := bytes.Index(data, []byte("TracerPid:"))
	if idx < 0 {
		return ""
	}
	rest := data[idx+len("TracerPid:"):]
	// Skip whitespace.
	for len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
		rest = rest[1:]
	}
	// Read digits.
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	pid := string(rest[:end])
	if pid != "" && pid != "0" {
		return "TracerPid=" + pid
	}
	return ""
}
