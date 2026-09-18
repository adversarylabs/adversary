package main

import (
	"os"

	"github.com/doomerlabs/adversary/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(cmd.ExitCode(err))
	}
}
