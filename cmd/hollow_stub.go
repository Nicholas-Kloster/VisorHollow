//go:build !windows

package cmd

import "fmt"

func Hollow(args []string) {
	fmt.Println("  visorhollow hollow: only available on Windows (cross-compile with GOOS=windows GOARCH=amd64)")
}
