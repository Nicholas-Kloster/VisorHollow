//go:build windows

package cmd

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Nicholas-Kloster/VisorHollow/detect"
)

func Check(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	sinceStr := fs.String("since", "5m", "look back this duration (e.g. 5m, 10m, 1h)")
	tech := fs.String("technique", "section", "technique context for expected event set: section | classic")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	since, err := time.ParseDuration(*sinceStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  invalid duration %q: %v\n", *sinceStr, err)
		os.Exit(1)
	}

	fmt.Printf("\n  VisorHollow — detection check (last %s, technique: %s)\n\n", *sinceStr, *tech)

	results, err := detect.Run(since, *tech)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [error] %v\n\n", err)
		os.Exit(1)
	}

	detect.Print(results)
}
