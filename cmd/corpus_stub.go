//go:build !windows

package cmd

import "fmt"

func Corpus(args []string) {
	fmt.Println("  visorhollow corpus: only available on Windows (cross-compile with GOOS=windows GOARCH=amd64)")
}
