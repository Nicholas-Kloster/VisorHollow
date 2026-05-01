//go:build windows

package detect

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Event IDs to check for in Microsoft-Windows-Sysmon/Operational
const (
	EventCreateRemoteThread = 8  // CreateRemoteThread into another process
	EventRawAccessRead      = 9  // RawAccessRead (not used here, included for completeness)
	EventOpenProcess        = 10 // OpenProcess access to another process
	EventProcessTampering   = 25 // Image is locked / process tampering
)

// SysmonEvent is a parsed detection artifact from the Sysmon event log.
type SysmonEvent struct {
	ID       int
	Time     time.Time
	Message  string
}

// CheckResult aggregates pass/fail per expected event.
type CheckResult struct {
	EventID  int
	Label    string
	Found    bool
	Count    int
	Events   []SysmonEvent
}

// Run queries the Sysmon event log for the three events that signal process hollowing.
// since: look back this far (e.g. 5 minutes)
// technique: "section" or "classic" — determines expected event set
func Run(since time.Duration, technique string) ([]CheckResult, error) {
	cutoff := time.Now().Add(-since)

	expected := expectedEvents(technique)
	results := make([]CheckResult, len(expected))

	events, err := querySysmon(cutoff)
	if err != nil {
		return nil, err
	}

	for i, exp := range expected {
		results[i] = CheckResult{
			EventID: exp.id,
			Label:   exp.label,
		}
		for _, ev := range events {
			if ev.ID == exp.id {
				results[i].Found = true
				results[i].Count++
				results[i].Events = append(results[i].Events, ev)
			}
		}
	}

	return results, nil
}

type expectedEvent struct {
	id    int
	label string
}

func expectedEvents(technique string) []expectedEvent {
	common := []expectedEvent{
		{EventOpenProcess, "OpenProcess access from injector (Event 10)"},
		{EventProcessTampering, "Process tampering / remote mapping detected (Event 25)"},
	}
	if technique == "classic" {
		// Classic adds CreateRemoteThread; section technique avoids it
		common = append([]expectedEvent{
			{EventCreateRemoteThread, "CreateRemoteThread into target process (Event 8)"},
		}, common...)
	}
	return common
}

// querySysmon shells out to PowerShell Get-WinEvent to avoid requiring wevtapi bindings.
func querySysmon(since time.Time) ([]SysmonEvent, error) {
	// PowerShell: query Sysmon operational log for events 8/10/25 after cutoff
	psScript := fmt.Sprintf(`
$since = [datetime]'%s'
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 200 -ErrorAction SilentlyContinue |
  Where-Object { $_.Id -in @(8, 10, 25) -and $_.TimeCreated -gt $since } |
  ForEach-Object { "$($_.Id)|$($_.TimeCreated.ToString('o'))|$($_.Message -replace '\n',' ')" }
`, since.Format("2006-01-02 15:04:05"))

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psScript)
	out, err := cmd.Output()
	if err != nil {
		// Non-zero exit often means no events found, not an error
		if len(out) == 0 {
			return nil, nil
		}
	}

	var events []SysmonEvent
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 3 {
			continue
		}

		var id int
		fmt.Sscanf(parts[0], "%d", &id)
		t, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(parts[1]))

		events = append(events, SysmonEvent{
			ID:      id,
			Time:    t,
			Message: parts[2],
		})
	}

	return events, nil
}

// Print renders CheckResult slice as a benchmark table.
func Print(results []CheckResult) {
	fmt.Println()
	fmt.Println("  Detection Benchmark Results")
	fmt.Println("  ───────────────────────────────────────────────────────────────")
	fmt.Printf("  %-6s %-8s %-6s  %s\n", "EvtID", "STATUS", "COUNT", "DESCRIPTION")
	fmt.Println("  ───────────────────────────────────────────────────────────────")

	allFound := true
	for _, r := range results {
		status := "MISS"
		if r.Found {
			status = "HIT"
		} else {
			allFound = false
		}
		fmt.Printf("  %-6d %-8s %-6d  %s\n", r.EventID, status, r.Count, r.Label)
	}

	fmt.Println("  ───────────────────────────────────────────────────────────────")
	if allFound {
		fmt.Println("  [RESULT]  ALL DETECTED — EDR/Sysmon config is catching this technique")
	} else {
		fmt.Println("  [RESULT]  PARTIAL / MISSED — gap in detection coverage")
	}
	fmt.Println()
}
