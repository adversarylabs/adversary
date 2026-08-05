package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"
)

// armSecondInterruptForceExit: after ctx is canceled (first Ctrl+C / SIGTERM),
// a second signal hard-exits with 130 so hung children cannot pin the process.
func armSecondInterruptForceExit(ctx context.Context) {
	go func() {
		<-ctx.Done()
		second := make(chan os.Signal, 1)
		signal.Notify(second, processSignals()...)
		defer signal.Stop(second)
		select {
		case <-second:
			fmt.Fprintln(os.Stderr, "forced exit (second interrupt)")
			os.Exit(130)
		case <-time.After(60 * time.Second):
			// Clean shutdown: stop listening.
		}
	}()
}
