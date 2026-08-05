package pipeline

import (
	"context"
	"os/exec"
)

func execCombined(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func execCombinedContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
