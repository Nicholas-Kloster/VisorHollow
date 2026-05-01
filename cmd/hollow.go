//go:build windows

package cmd

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Nicholas-Kloster/VisorHollow/detect"
	"github.com/Nicholas-Kloster/VisorHollow/payload"
	"github.com/Nicholas-Kloster/VisorHollow/technique"
)

func Hollow(args []string) {
	fs := flag.NewFlagSet("hollow", flag.ExitOnError)
	tech := fs.String("technique", "section", "injection technique: section | classic")
	target := fs.String("target", "notepad.exe", "process to spawn and inject into")
	check := fs.Bool("check", false, "query Sysmon event log after injection")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	fmt.Printf("\n  VisorHollow — injection starting\n\n")

	before := time.Now()

	var err error
	switch *tech {
	case "section":
		err = technique.SectionInject(*target, payload.Shellcode)
	case "classic":
		err = technique.ClassicInject(*target, payload.Shellcode)
	default:
		fmt.Fprintf(os.Stderr, "  unknown technique: %s (use 'section' or 'classic')\n", *tech)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "\n  [error] %v\n\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n  [done]  injection complete\n")

	if *check {
		fmt.Printf("  [check] waiting 3s for Sysmon events to flush...\n")
		time.Sleep(3 * time.Second)

		since := time.Since(before) + 5*time.Second
		results, err := detect.Run(since, *tech)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [check error] %v\n", err)
			return
		}
		detect.Print(results)
	}
}
