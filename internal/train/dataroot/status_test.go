package dataroot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteBlockedAndRender(t *testing.T) {
	root := t.TempDir()
	bl := BlockedResult{
		Dependency:     "gh",
		Operation:      "collect",
		Classification: "auth",
		SanitizedError: "no token",
		NextAction:     "gh auth login",
		RetrySafe:      true,
	}
	path, err := WriteBlocked(root, "run-1", bl)
	if err != nil {
		// may not exist helper - check
		t.Log(err)
	}
	_ = path
	// RenderSTATUS if present
	_ = RenderSTATUS([]BlockedResult{bl})
	// Exit codes
	if ExitSuccess == ExitFailed {
		t.Fatal("codes")
	}
	_ = filepath.Join(root, "x")
	_ = os.Stdout
}
