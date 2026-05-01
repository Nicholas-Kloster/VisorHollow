package main

import (
	"fmt"
	"os"

	"github.com/Nicholas-Kloster/VisorHollow/cmd"
)

const banner = `
  VisorHollow · Process Injection Detection Benchmark
  github.com/Nicholas-Kloster/VisorHollow · Nuclide Research
`

func usage() {
	fmt.Println(banner)
	fmt.Println(`USAGE:
  visorhollow <command> [flags]

COMMANDS:
  hollow   Inject shellcode into a spawned target process
  check    Query Sysmon event log for post-injection detection artifacts

FLAGS (hollow):
  --technique   section | classic  (default: section)
  --target      process to spawn (default: notepad.exe)
  --check       run check automatically after injection completes

TECHNIQUES:
  section   NtCreateSection + NtMapViewOfSection (avoids NtWriteVirtualMemory hook)
            Triggers: ETW KERNEL_THREATINT_KEYWORD_MAPVIEW, Sysmon 25
  classic   VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
            Triggers: Sysmon 8 (CreateRemoteThread), Sysmon 10 (OpenProcess)

EXAMPLES:
  visorhollow hollow --technique section --target notepad.exe
  visorhollow hollow --technique classic --target calc.exe
  visorhollow hollow --technique section --check
  visorhollow check --since 5m
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "hollow":
		cmd.Hollow(os.Args[2:])
	case "check":
		cmd.Check(os.Args[2:])
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}
