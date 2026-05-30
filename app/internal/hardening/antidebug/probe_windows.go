//go:build windows

package antidebug

import "golang.org/x/sys/windows"

func init() { Probe = probeWindows }

// probeWindows checks the cheap IsDebuggerPresent API plus the remote
// debugger query. The richer PEB BeingDebugged / NtGlobalFlag /
// NtQueryInformationProcess(ProcessDebugPort) probes documented in
// TECHNICAL.md §8.1 are tracked in a follow-up; the kernel32 routes
// are good enough to catch unsophisticated attaches.
func probeWindows() string {
	if windows.IsDebuggerPresent() {
		return "IsDebuggerPresent"
	}
	var present bool
	cur, _ := windows.GetCurrentProcess(), error(nil)
	if err := windows.CheckRemoteDebuggerPresent(cur, &present); err == nil && present {
		return "CheckRemoteDebuggerPresent"
	}
	return ""
}
