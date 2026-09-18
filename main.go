package main

import (
	"os"

	"github.com/doomerlabs/doomer/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(cmd.ExitCode(err))
	}
}
