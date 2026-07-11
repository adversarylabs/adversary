//go:build !windows

package cmd

import (
	"os"
	"syscall"
)

func processSignals() []os.Signal { return []os.Signal{os.Interrupt, syscall.SIGTERM} }
