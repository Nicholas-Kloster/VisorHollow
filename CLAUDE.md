# VisorHollow

Go-based detection benchmark for process injection on Windows x64. Two execution modes: `section` (NtMapViewOfSection variant — avoids `NtWriteVirtualMemory`, relies on ETW Threat Intelligence + Sysmon Event 25) and `classic` (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread — the canonical noisy baseline). Plus **HollowCorpus** — 6-tier injection technique ladder with coverage matrix, run with one command to surface which tier your detection stack stops at.

The Windows red-team / detection-engineering counterpart to the rest of the (Linux/cloud-focused) NuClide chain.

## Language
Go (Windows x64 runtime; cross-compile from Linux/macOS supported)

## Build & Run
```
# Windows native
go build -o visorhollow.exe .

# Cross-compile from Linux/macOS
GOOS=windows GOARCH=amd64 go build -o visorhollow.exe .

# Run both techniques back-to-back with auto-check
visorhollow.exe -all -check

# Run check standalone (after manual test)
visorhollow.exe -check

# HollowCorpus — full 6-tier ladder
visorhollow.exe -corpus
```

## Layout
```
main.go        # CLI entry + flag parsing
cmd/           # subcommand implementations (section / classic / corpus / check)
technique/     # technique implementations (NtMapViewOfSection, WriteProcessMemory, etc.)
payload/       # payload generation + shellcode utilities
detect/        # Sysmon/ETW event log query + pass/fail evaluation
corpus/        # HollowCorpus 6-tier ladder + coverage matrix
visorhollow.exe # prebuilt Windows binary (committed for users without a Windows build environment)
```

## Claude Code Notes
- Check README for the technique deep-dives (API call sequences, residual artifacts, detection signals) and the **Sysmon Config (Minimum Required)** section
- Output is pass/fail per Sysmon event ID — pipe into VisorLog ingest for the broader chain
- The `-corpus` mode is the headline feature: get a coverage matrix for your detection stack in one command
- Built with [Claude Code](https://claude.ai/code)
