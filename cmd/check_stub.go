//go:build !windows

package cmd

import "fmt"

func Check(args []string) {
	fmt.Println("  visorhollow check: only available on Windows (cross-compile with GOOS=windows GOARCH=amd64)")
}
