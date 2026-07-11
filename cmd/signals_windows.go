//go:build windows

package cmd

import "os"

func processSignals() []os.Signal { return []os.Signal{os.Interrupt} }
