//go:build windows

package cmd

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Nicholas-Kloster/VisorHollow/corpus"
	"github.com/Nicholas-Kloster/VisorHollow/detect"
	"github.com/Nicholas-Kloster/VisorHollow/payload"
)

func Corpus(args []string) {
	if len(args) == 0 {
		fmt.Println("  usage: visorhollow corpus <list|run> [flags]")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		corpusList(args[1:])
	case "run":
		corpusRun(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "  unknown corpus command: %s\n", args[0])
		os.Exit(1)
	}
}

func corpusList(_ []string) {
	fmt.Printf("\n  HollowCorpus — %d techniques\n\n", len(corpus.Catalog))
	fmt.Printf("  %-6s %-38s %-20s %s\n", "Tier", "Name", "ExpectEvents", "Evasion")
	fmt.Println("  ─────────────────────────────────────────────────────────────────────")
	for _, t := range corpus.Catalog {
		evts := formatEvents(t.ExpectEvents)
		evasion := "-"
		if len(t.Evasion) > 0 {
			evasion = t.Evasion[0]
		}
		fmt.Printf("  T%-5d %-38s %-20s %s\n", t.Tier, truncateStr(t.Name, 38), evts, evasion)
	}
	fmt.Println()
}

func corpusRun(args []string) {
	fs := flag.NewFlagSet("corpus run", flag.ExitOnError)
	target := fs.String("target", "notepad.exe", "process to spawn for each technique")
	tierStr := fs.String("tier", "", "run only this tier range, e.g. '1-3' or '2'")
	id := fs.String("id", "", "run a single technique by ID (e.g. T1055-03-apc)")
	fs.Parse(args)

	techniques := selectTechniques(*tierStr, *id)
	if len(techniques) == 0 {
		fmt.Fprintln(os.Stderr, "  no techniques matched the given filter")
		os.Exit(1)
	}

	fmt.Printf("\n  HollowCorpus run — %d techniques — target: %s\n\n", len(techniques), *target)

	var matrixRows []detect.MatrixRow

	for i, tech := range techniques {
		fmt.Printf("  [%d/%d] T%d: %s\n", i+1, len(techniques), tech.Tier, tech.Name)

		before := time.Now()
		runErr := tech.Run(*target, payload.Shellcode)
		if runErr != nil {
			fmt.Printf("        [skip] %v\n\n", runErr)
			// Still add a row with all misses so the matrix shows the gap
			matrixRows = append(matrixRows, detect.MatrixRow{
				TechniqueID:   tech.ID,
				TechniqueName: tech.Name,
				Tier:          tech.Tier,
				ExpectEvents:  tech.ExpectEvents,
				Results:       map[int]detect.CheckResult{},
			})
			continue
		}

		fmt.Printf("        waiting 3s for Sysmon flush...\n")
		time.Sleep(3 * time.Second)

		since := time.Since(before) + 5*time.Second
		results, err := detect.Run(since, "")
		if err != nil {
			fmt.Printf("        [check error] %v\n\n", err)
		}

		row := detect.MatrixRow{
			TechniqueID:   tech.ID,
			TechniqueName: tech.Name,
			Tier:          tech.Tier,
			ExpectEvents:  tech.ExpectEvents,
			Results:       make(map[int]detect.CheckResult),
		}
		for _, r := range results {
			row.Results[r.EventID] = r
		}
		matrixRows = append(matrixRows, row)

		// Per-technique summary
		for _, r := range results {
			status := "MISS"
			if r.Found {
				status = "HIT "
			}
			fmt.Printf("        E%-3d %s\n", r.EventID, status)
		}
		fmt.Println()

		// Brief pause between techniques
		time.Sleep(2 * time.Second)
	}

	detect.PrintMatrix(matrixRows)
}

func selectTechniques(tierRange, id string) []corpus.Technique {
	if id != "" {
		for _, t := range corpus.Catalog {
			if t.ID == id {
				return []corpus.Technique{t}
			}
		}
		return nil
	}

	if tierRange == "" {
		return corpus.Catalog
	}

	// Parse "1-3" or "2"
	parts := strings.SplitN(tierRange, "-", 2)
	lo, err1 := strconv.Atoi(parts[0])
	hi := lo
	if len(parts) == 2 {
		hi, _ = strconv.Atoi(parts[1])
	}
	if err1 != nil {
		return corpus.Catalog
	}

	var out []corpus.Technique
	for _, t := range corpus.Catalog {
		if t.Tier >= lo && t.Tier <= hi {
			out = append(out, t)
		}
	}
	return out
}

func formatEvents(ids []int) string {
	var parts []string
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("E%d", id))
	}
	return strings.Join(parts, " ")
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
