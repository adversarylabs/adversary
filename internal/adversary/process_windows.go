//go:build windows

package adversary

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func platformShell() ([]string, error) {
	path, err := exec.LookPath("cmd.exe")
	if err != nil {
		return nil, fmt.Errorf("host shell is unavailable: %w", err)
	}
	return []string{path}, nil
}

func validateExecutable(path string) error {
	_, err := executableFileInfo(path)
	if err != nil {
		return err
	}
	ext := strings.ToLower(filepath.Ext(path))
	pathext := strings.ToLower(os.Getenv("PATHEXT"))
	if pathext == "" {
		pathext = ".com;.exe;.bat;.cmd"
	}
	for _, allowed := range strings.Split(pathext, ";") {
		if ext == strings.TrimSpace(allowed) {
			return nil
		}
	}
	return fmt.Errorf("extension %q is not executable under PATHEXT", ext)
}

func configureProcess(cmd *exec.Cmd) {}

func supervisedProcessGroup(cmd *exec.Cmd) int {
	if cmd.Process == nil {
		return 0
	}
	return cmd.Process.Pid
}

// Windows currently has no job-object dependency. Cancellation kills the
// direct child; the documented contract requires Windows adversaries not to
// detach descendants until job-object supervision is introduced.
func requestProcessTermination(cmd *exec.Cmd, _ int) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func killProcessTree(cmd *exec.Cmd, group int) { requestProcessTermination(cmd, group) }
