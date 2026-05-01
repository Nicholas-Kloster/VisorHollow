[![Claude Code Friendly](https://img.shields.io/badge/Claude_Code-Friendly-blueviolet?logo=anthropic&logoColor=white)](https://claude.ai/code)
[![Go Report Card](https://goreportcard.com/badge/github.com/Nicholas-Kloster/VisorHollow)](https://goreportcard.com/report/github.com/Nicholas-Kloster/VisorHollow)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

```
  Process Injection Detection Benchmark · Windows x64
  github.com/Nicholas-Kloster/VisorHollow · Nuclide Research
```

**VisorHollow** is a Go-based detection benchmark for process injection techniques on Windows x64. It executes injection variants and queries the Sysmon event log to determine whether your EDR/SIEM configuration caught them. Pass/fail per event ID — not theory.

**HollowCorpus** extends this into a full 6-tier technique ladder. Run the entire ladder with one command and get a coverage matrix showing exactly which tier your detection stack stops working at.

---

## Techniques

| Flag | Technique | Key APIs | Primary Detection Signal |
|------|-----------|----------|--------------------------|
| `section` | NtMapViewOfSection (shared section) | NtCreateSection, NtMapViewOfSection ×2, SetThreadContext | ETW `KERNEL_THREATINT_KEYWORD_MAPVIEW`, Sysmon Event 25 |
| `classic` | VirtualAllocEx + WriteProcessMemory | VirtualAllocEx (RWX), WriteProcessMemory, CreateRemoteThread | Sysmon Event 8 (CreateRemoteThread), Event 10 (OpenProcess) |

### `section` — NtMapViewOfSection variant

```
CreateProcess (suspended)
  → NtCreateSection (anonymous, pagefile-backed, RWX)
  → NtMapViewOfSection → current process   (local RWX mapping)
  → memcpy shellcode into local mapping
  → NtMapViewOfSection → target process    (remote RX mapping)
  → SetThreadContext: RIP = remote mapping address
  → ResumeThread
```

**Why it matters:** Avoids `NtWriteVirtualMemory` entirely — the cross-process write that most EDR hooks target. The local→remote section pattern means shellcode bytes never cross process boundaries via a monitored syscall. Detection depends on ETW Threat Intelligence (`KERNEL_THREATINT_KEYWORD_MAPVIEW`) or behavioral correlation rather than API hook.

**Residual artifacts (still detectable):**
- Anonymous RWX VAD entry (no backing file path)
- Thread entry point outside any loaded PE module
- PEB.ImageBaseAddress mismatch if original image was unmapped
- Sysmon Event 25: ProcessTampering on remote executable mapping

### `classic` — WriteProcessMemory variant

```
CreateProcess (suspended)
  → VirtualAllocEx (RWX)
  → WriteProcessMemory
  → CreateRemoteThread (start = allocated RWX region)
  → ResumeThread
```

The canonical technique. Loud — every EDR watches Event 8. Useful as a baseline: if `classic` is missed, your Sysmon config is broken.

---

## Build

```bash
# Windows native
go build -o visorhollow.exe .

# Cross-compile from Linux/macOS
GOOS=windows GOARCH=amd64 go build -o visorhollow.exe .
```

Requires Go 1.21+. No CGO. Single static binary. Only dependency: `golang.org/x/sys`.

---

## HollowCorpus

A 6-tier injection technique ladder. Each tier removes one detection signal from the previous, building from the loudest possible path to full user-mode hook bypass.

### Tier ladder

| Tier | Technique | APIs | Evasion added | Expected events |
|------|-----------|------|---------------|-----------------|
| T1 | WriteProcessMemory + CreateRemoteThread | VirtualAllocEx, WPM, CRT | — | E8, E10 |
| T2 | NtMapViewOfSection + SetThreadContext | NtCreateSection, NtMapViewOfSection | no NtWriteVirtualMemory | E10, E25 |
| T3 | NtMapViewOfSection + QueueUserAPC | NtCreateSection, NtMapViewOfSection, QueueUserAPC | no CreateRemoteThread | E10, E25 |
| T4 | Thread Context Hijacking | OpenThread, SuspendThread, WPM, STC | no new process, no section object | E10 |
| T5 | Module Stomping | VirtualProtectEx, WPM, CRT | no anonymous RWX VAD, E25 blind | E8, E10 |
| T6 | Direct Syscall | NtCreateSection (direct), NtMapViewOfSection (direct) | ntdll user-mode hooks bypassed entirely | E10, E25 |

### Commands

```bash
visorhollow corpus list                      # show all techniques with metadata
visorhollow corpus run                       # run all 6 tiers
visorhollow corpus run --tier 1-3            # run tiers 1-3 only
visorhollow corpus run --id T1055-04-hijack  # run a single technique by ID
visorhollow corpus run --target calc.exe     # use a different target process
```

### Sample output

```
  HollowCorpus run — 6 techniques — target: notepad.exe

  [1/6] T1: WriteProcessMemory + CreateRemoteThread
        E8   HIT
        E10  HIT

  [2/6] T2: NtMapViewOfSection + SetThreadContext
        E10  HIT
        E25  HIT

  [3/6] T3: NtMapViewOfSection + QueueUserAPC
        E10  HIT
        E25  HIT

  [4/6] T4: Thread Context Hijacking
        E10  MISS

  ...

  ═══════════════════════════════════════════════════════════════════════
  HollowCorpus Detection Coverage Matrix
  ═══════════════════════════════════════════════════════════════════════
  Tier  Technique                               E8    E10   E25   Score
  ───────────────────────────────────────────────────────────────────────
  T1    WriteProcessMemory + CreateRemoteThread  HIT   HIT   ---   2/2
  T2    NtMapViewOfSection + SetThreadContext    ---   HIT   HIT   2/2
  T3    NtMapViewOfSection + QueueUserAPC        ---   HIT   HIT   2/2
  T4    Thread Context Hijacking                 ---   MISS  ---   0/1
  T5    Module Stomping (DLL .text overwrite)    HIT   HIT   ---   2/2
  T6    Direct Syscall (bypass ntdll hooks)      ---   MISS  MISS  0/2
  ───────────────────────────────────────────────────────────────────────
  Total coverage: 7/10 events detected
  [RESULT]  First undetected tier: T4
            Techniques at T4+ evade your current detection stack.
  ═══════════════════════════════════════════════════════════════════════
```

**Reading the matrix:** `First undetected tier: T4` means your Sysmon/EDR config catches everything up to and including thread hijacking's expected events — but T4 itself slips through. Fix: add Event 10 coverage for `OpenProcess` with `PROCESS_ALL_ACCESS` from non-system processes, and ensure ETW Threat Intelligence is enabled for T6.

---

## Usage

```
COMMANDS:
  hollow   Inject shellcode into a spawned target process
  check    Query Sysmon event log for post-injection detection artifacts

FLAGS (hollow):
  --technique   section | classic  (default: section)
  --target      process to spawn   (default: notepad.exe)
  --check       run check automatically after injection completes
```

### Run both techniques back-to-back with auto-check

```
visorhollow hollow --technique section --target notepad.exe --check
visorhollow hollow --technique classic --target calc.exe --check
```

### Run check standalone (after manual test)

```
visorhollow check --since 10m --technique section
```

### Sample output

```
  VisorHollow — injection starting

  [technique] NtMapViewOfSection
  [target]    notepad.exe
  [payload]   271 bytes
  [spawned]   PID 4812 TID 4816 (suspended)
  [section]   handle 0x6c
  [local map] 0x22b0a4e0000 (RWX, 271 bytes)
  [copied]    shellcode written to local mapping
  [remote map] 0x22b0a4e0000 (RX, PID 4812)
  [ctx]       RIP → 0x22b0a4e0000
  [resumed]   PID 4812 executing at 0x22b0a4e0000

  [done]  injection complete
  [check] waiting 3s for Sysmon events to flush...

  Detection Benchmark Results
  ───────────────────────────────────────────────────────────────
  EvtID  STATUS   COUNT   DESCRIPTION
  ───────────────────────────────────────────────────────────────
  10     HIT      1       OpenProcess access from injector (Event 10)
  25     HIT      1       Process tampering / remote mapping detected (Event 25)
  ───────────────────────────────────────────────────────────────
  [RESULT]  ALL DETECTED — EDR/Sysmon config is catching this technique
```

---

## Sysmon Config (Minimum Required)

To catch the `section` technique, your Sysmon config needs **at minimum**:

```xml
<!-- Event 25: ProcessTampering (added in Sysmon v13) -->
<ProcessTampering onmatch="include">
  <all/>
</ProcessTampering>

<!-- Event 10: ProcessAccess — catches OpenProcess from injector -->
<ProcessAccess onmatch="include">
  <GrantedAccess condition="is">0x1FFFFF</GrantedAccess>
</ProcessAccess>
```

For the `classic` technique, add:

```xml
<!-- Event 8: CreateRemoteThread -->
<CreateRemoteThread onmatch="include">
  <all/>
</CreateRemoteThread>
```

**Detection gap:** Sysmon alone won't catch `section` without ProcessTampering (Event 25) — added in Sysmon v13. If you're running Sysmon v12 or older, `section` will be a MISS.

---

## Payload

Default payload: `WinExec("calc.exe", SW_SHOW)` via PEB-walk API resolution.

To use a custom shellcode, replace `payload.Shellcode` in `payload/shellcode.go`:

```go
var Shellcode = []byte{
    // your bytes here
}
```

Generate alternatives:
```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f hex -b '\x00'
msfvenom -p windows/x64/messagebox TEXT="hollow confirmed" TITLE="VisorHollow" -f hex
```

---

## Detection Mapping

| Sysmon Event | Technique | What triggers it |
|---|---|---|
| 8 — CreateRemoteThread | classic | Thread creation with start address outside loaded PE |
| 10 — ProcessAccess | both | OpenProcess(PROCESS_ALL_ACCESS) on target |
| 25 — ProcessTampering | section | Remote executable mapping via NtMapViewOfSection |

**ETW coverage (requires Defender / compatible EDR):**  
`KERNEL_THREATINT_KEYWORD_MAPVIEW` fires on NtMapViewOfSection when source != target process. This is the primary signal for the section technique when Sysmon Event 25 is not available.

---

## Ecosystem

| Tool | Role |
|------|------|
| [JAXEN](https://github.com/Nicholas-Kloster/JAXEN) | Shodan harvest + empire.db |
| [VisorSD](https://github.com/Nicholas-Kloster/VisorSD) | Severity-ranked AI/LLM audit |
| [VisorCorpus](https://github.com/Nicholas-Kloster/VisorCorpus) | Adversarial LLM prompt corpus |
| [VisorPlus](https://github.com/Nicholas-Kloster/VisorPlus) | Unified AI/LLM recon orchestrator |
| [BARE](https://github.com/Nicholas-Kloster/BARE) | Semantic exploit matching |
| [aimap](https://github.com/Nicholas-Kloster/aimap) | AI/ML service enumerator |

---

## License

MIT — see [LICENSE](LICENSE)
