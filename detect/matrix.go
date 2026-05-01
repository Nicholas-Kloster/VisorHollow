package detect

import (
	"fmt"
	"strings"
)

// MatrixRow is one technique's results across all expected event IDs.
type MatrixRow struct {
	TechniqueID   string
	TechniqueName string
	Tier          int
	ExpectEvents  []int
	Results       map[int]CheckResult // event ID → result
}

// PrintMatrix renders the full coverage matrix.
func PrintMatrix(rows []MatrixRow) {
	if len(rows) == 0 {
		return
	}

	// Collect all event IDs across all rows for column headers
	eventSet := map[int]struct{}{}
	for _, row := range rows {
		for _, eid := range row.ExpectEvents {
			eventSet[eid] = struct{}{}
		}
	}
	eventCols := []int{8, 10, 25} // fixed order

	fmt.Println()
	fmt.Println("  ═══════════════════════════════════════════════════════════════════════")
	fmt.Println("  HollowCorpus Detection Coverage Matrix")
	fmt.Println("  ═══════════════════════════════════════════════════════════════════════")
	fmt.Printf("  %-6s  %-38s", "Tier", "Technique")
	for _, eid := range eventCols {
		fmt.Printf("  E%-3d", eid)
	}
	fmt.Printf("  Score\n")
	fmt.Println("  ───────────────────────────────────────────────────────────────────────")

	firstMiss := -1
	for _, row := range rows {
		fmt.Printf("  T%-5d %-38s", row.Tier, truncate(row.TechniqueName, 38))

		hit, expected := 0, 0
		for _, eid := range eventCols {
			res, ok := row.Results[eid]
			isExpected := contains(row.ExpectEvents, eid)

			if isExpected {
				expected++
				if ok && res.Found {
					hit++
					fmt.Printf("  HIT ")
				} else {
					fmt.Printf("  MISS")
					if firstMiss == -1 {
						firstMiss = row.Tier
					}
				}
			} else {
				fmt.Printf("  --- ")
			}
		}
		fmt.Printf("  %d/%d\n", hit, expected)
	}

	fmt.Println("  ───────────────────────────────────────────────────────────────────────")

	// Summary
	totalHit, totalExpected := 0, 0
	for _, row := range rows {
		for _, eid := range row.ExpectEvents {
			totalExpected++
			if res, ok := row.Results[eid]; ok && res.Found {
				totalHit++
			}
		}
	}
	fmt.Printf("  Total coverage: %d/%d events detected\n", totalHit, totalExpected)

	if firstMiss == -1 {
		fmt.Println("  [RESULT]  ALL TECHNIQUES DETECTED — full coverage")
	} else {
		fmt.Printf("  [RESULT]  First undetected tier: T%d\n", firstMiss)
		fmt.Printf("            Techniques at T%d+ evade your current detection stack.\n", firstMiss)
	}
	fmt.Println("  ═══════════════════════════════════════════════════════════════════════")
	fmt.Println()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s + strings.Repeat(" ", n-len(s))
	}
	return s[:n-1] + "…"
}

func contains(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}
