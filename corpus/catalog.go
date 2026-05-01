package corpus

import "github.com/Nicholas-Kloster/VisorHollow/technique"

// Technique describes one entry in the injection corpus.
type Technique struct {
	ID           string
	Name         string
	Tier         int
	APIs         []string // syscalls/APIs used
	Evasion      []string // what detection vectors this avoids vs the previous tier
	ExpectEvents []int    // Sysmon event IDs that SHOULD fire if detection is working
	Description  string
	Run          func(target string, shellcode []byte) error
}

// Catalog is the ordered injection technique ladder from loudest to most evasive.
// Each tier removes one detection signal that the previous tier exposed.
var Catalog = []Technique{
	{
		ID:   "T1055-01-classic",
		Name: "WriteProcessMemory + CreateRemoteThread",
		Tier: 1,
		APIs: []string{
			"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
		},
		Evasion:      []string{},
		ExpectEvents: []int{8, 10},
		Description:  "Canonical process injection. RWX alloc in target, WPM write, CRT execution. Loudest possible path — baseline for 'is Sysmon working at all'.",
		Run:          technique.ClassicInject,
	},
	{
		ID:   "T1055-02-section",
		Name: "NtMapViewOfSection + SetThreadContext",
		Tier: 2,
		APIs: []string{
			"NtCreateSection", "NtMapViewOfSection", "SetThreadContext", "ResumeThread",
		},
		Evasion: []string{
			"no-NtWriteVirtualMemory (avoids cross-process write hook)",
		},
		ExpectEvents: []int{10, 25},
		Description:  "Anonymous pagefile-backed section shared between injector and target. No NtWriteVirtualMemory call — bypasses EDR hooks on the write path. SetThreadContext redirects main thread RIP instead of spawning a new thread.",
		Run:          technique.SectionInject,
	},
	{
		ID:   "T1055-03-apc",
		Name: "NtMapViewOfSection + QueueUserAPC",
		Tier: 3,
		APIs: []string{
			"NtCreateSection", "NtMapViewOfSection", "QueueUserAPC", "NtAlertThread",
		},
		Evasion: []string{
			"no-NtWriteVirtualMemory",
			"no-CreateRemoteThread (avoids Event 8)",
		},
		ExpectEvents: []int{10, 25},
		Description:  "Same section technique as Tier 2, but APC replaces SetThreadContext. APC fires when the target thread enters an alertable wait state. NtAlertThread forces the drain. Eliminates Event 8 (CreateRemoteThread) while preserving section evasion.",
		Run:          technique.APCInject,
	},
	{
		ID:   "T1055-04-hijack",
		Name: "Thread Context Hijacking (existing thread)",
		Tier: 4,
		APIs: []string{
			"CreateToolhelp32Snapshot", "OpenThread", "SuspendThread",
			"VirtualAllocEx", "WriteProcessMemory", "GetThreadContext", "SetThreadContext",
		},
		Evasion: []string{
			"no-CreateRemoteThread",
			"no-new-process (target spawned normally — no suspended-process tell)",
			"no-section-object (no ETW MAPVIEW signal)",
		},
		ExpectEvents: []int{10},
		Description:  "Target process is spawned normally and allowed to fully initialize. An existing thread is suspended, its RIP redirected into VirtualAllocEx memory, then resumed. No section object means ETW KERNEL_THREATINT_KEYWORD_MAPVIEW and Event 25 are blind. Only Event 10 (OpenProcess) and behavioral analysis can catch this.",
		Run:          technique.HijackInject,
	},
	{
		ID:   "T1055-05-stomp",
		Name: "Module Stomping (DLL .text overwrite)",
		Tier: 5,
		APIs: []string{
			"CreateToolhelp32Snapshot", "VirtualProtectEx", "WriteProcessMemory", "CreateRemoteThread",
		},
		Evasion: []string{
			"no-anonymous-RWX-VAD (shellcode in named file-backed region)",
			"no-section-object",
			"Event 25 blind (VAD shows DLL path, not Anonymous)",
		},
		ExpectEvents: []int{8, 10},
		Description:  "Shellcode overwrites a loaded DLL's .text section via VirtualProtectEx + WriteProcessMemory. The VAD entry retains the original DLL file path — no anonymous RWX region appears. Event 25 does not fire. Detection requires on-disk vs in-memory module integrity checking (hash mismatch) or behavioral correlation of CreateRemoteThread starting inside a known-clean DLL.",
		Run:          technique.StompInject,
	},
	{
		ID:   "T1055-06-direct-syscall",
		Name: "Direct Syscall (bypass ntdll user-mode hooks)",
		Tier: 6,
		APIs: []string{
			"NtCreateSection (direct)", "NtMapViewOfSection (direct)", "SetThreadContext",
		},
		Evasion: []string{
			"no-NtWriteVirtualMemory",
			"no-CreateRemoteThread",
			"ntdll-user-mode-hooks-bypassed (EDR callbacks never execute)",
		},
		ExpectEvents: []int{10, 25},
		Description:  "Extracts raw syscall numbers from ntdll stubs at runtime, builds 11-byte trampolines, issues syscall instruction directly from own memory. EDR user-mode hooks in ntdll.dll never execute — only kernel-level ETW (KERNEL_THREATINT_KEYWORD_MAPVIEW) and Sysmon's kernel driver can catch the remote mapping. If Event 25 is a MISS here, your detection stack relies entirely on user-mode hooks.",
		Run:          technique.DirectSyscallInject,
	},
}
