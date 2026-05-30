//go:build darwin

package antidebug

import (
	"syscall"
	"unsafe"
)

func init() { Probe = probeDarwin }

// kinfoProcP_TRACED is the P_TRACED bit set by xnu when the process is
// being traced. We only need a few bytes from kinfo_proc — enough to
// reach the kp_proc.p_flag field.
const kinfoProcP_TRACED = 0x800

// probeDarwin uses sysctl(KERN_PROC, KERN_PROC_PID, getpid()) to fetch
// kinfo_proc for ourselves and checks the P_TRACED flag inside it.
//
// We hand-decode just the byte offsets we need rather than pulling in
// cgo or replicating the (large) kinfo_proc layout. Offset 32 is
// p_flag, a 32-bit little-endian int on amd64/arm64 darwin.
func probeDarwin() string {
	mib := []int32{
		1,  // CTL_KERN
		14, // KERN_PROC
		1,  // KERN_PROC_PID
		int32(syscall.Getpid()),
	}

	var n uintptr
	// First call: get required size.
	_, _, errno := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
		0, uintptr(unsafe.Pointer(&n)),
		0, 0,
	)
	if errno != 0 || n == 0 {
		return ""
	}

	buf := make([]byte, n)
	_, _, errno = syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)),
		0, 0,
	)
	if errno != 0 {
		return ""
	}
	if len(buf) < 36 {
		return ""
	}

	pFlag := uint32(buf[32]) | uint32(buf[33])<<8 | uint32(buf[34])<<16 | uint32(buf[35])<<24
	if pFlag&kinfoProcP_TRACED != 0 {
		return "P_TRACED set"
	}
	return ""
}
