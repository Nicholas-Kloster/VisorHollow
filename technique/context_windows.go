//go:build windows

package technique

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CONTEXT x64 structure for GetThreadContext / SetThreadContext.
// golang.org/x/sys/windows doesn't export a complete CONTEXT struct,
// so we define the full layout here (matching winnt.h CONTEXT for AMD64).
type CONTEXT struct {
	P1Home               uint64
	P2Home               uint64
	P3Home               uint64
	P4Home               uint64
	P5Home               uint64
	P6Home               uint64
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	// FltSave / XSAVE area (512 bytes, 16-byte aligned)
	_xmm [512]byte
}

var (
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procGetThreadContext = kernel32.NewProc("GetThreadContext")
	procSetThreadContext = kernel32.NewProc("SetThreadContext")
)

func getThreadContext(thread windows.Handle) (*CONTEXT, error) {
	ctx := &CONTEXT{}
	ctx.ContextFlags = CONTEXT_FULL

	r1, _, err := procGetThreadContext.Call(
		uintptr(thread),
		uintptr(unsafe.Pointer(ctx)),
	)
	if r1 == 0 {
		return nil, fmt.Errorf("GetThreadContext: %w", err)
	}
	return ctx, nil
}

func setThreadContext(thread windows.Handle, ctx *CONTEXT) error {
	r1, _, err := procSetThreadContext.Call(
		uintptr(thread),
		uintptr(unsafe.Pointer(ctx)),
	)
	if r1 == 0 {
		return fmt.Errorf("SetThreadContext: %w", err)
	}
	return nil
}

// resolveExecutable returns the full path for a process name.
// If name is already absolute, returns it unchanged.
// Otherwise, checks System32 then falls back to passing name directly
// (CreateProcess handles PATH search internally).
func resolveExecutable(name string) (string, error) {
	if filepath.IsAbs(name) {
		return name, nil
	}

	sysDir, err := windows.GetSystemDirectory()
	if err == nil {
		candidate := filepath.Join(sysDir, name)
		if _, err2 := windows.GetFileAttributes(strToUTF16(candidate)); err2 == nil {
			return candidate, nil
		}
	}

	// Let CreateProcess search PATH
	return name, nil
}

func strToUTF16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}
