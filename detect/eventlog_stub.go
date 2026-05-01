//go:build !windows

package detect

import (
	"fmt"
	"time"
)

type SysmonEvent struct {
	ID      int
	Time    time.Time
	Message string
}

type CheckResult struct {
	EventID int
	Label   string
	Found   bool
	Count   int
	Events  []SysmonEvent
}

func Run(since time.Duration, technique string) ([]CheckResult, error) {
	return nil, fmt.Errorf("detect: only available on Windows")
}

func Print(results []CheckResult) {}
