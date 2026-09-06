//go:build linux || darwin

package archiveutil

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// Umask is process-wide, so exercise the real extraction/publication paths in
// an isolated test process instead of changing permissions for parallel tests.
func TestRestrictiveUmaskSubprocess(t *testing.T) {
	const child = "ADVERSARY_TEST_RESTRICTIVE_UMASK"
	if os.Getenv(child) == "1" {
		syscall.Umask(0077)
		t.Run("extract", TestPreservesExecutableMode)
		t.Run("publish", TestPublishSealedTransition)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRestrictiveUmaskSubprocess$", "-test.v")
	cmd.Env = append(os.Environ(), child+"=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("restrictive-umask extraction/publication failed: %v\n%s", err, output)
	}
}
