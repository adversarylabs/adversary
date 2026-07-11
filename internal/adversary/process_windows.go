//go:build windows

package adversary

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

func PlatformShell(lookPath func(string) (string, error)) ([]string, error) {
	path, err := lookPath("cmd.exe")
	if err != nil {
		return nil, fmt.Errorf("host shell is unavailable: %w", err)
	}
	return []string{path}, nil
}

func ValidateExecutable(path, pathext string) error {
	_, err := executableFileInfo(path)
	if err != nil {
		return err
	}
	ext := strings.ToLower(filepath.Ext(path))
	pathext = strings.ToLower(pathext)
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

func supervisedProcessGroup(process RunningProcess) int { return process.PID() }

// Windows currently has no job-object dependency. Cancellation kills the
// direct child; the documented contract requires Windows adversaries not to
// detach descendants until job-object supervision is introduced.
func requestProcessTermination(process RunningProcess, _ int) { _ = process.Kill() }

func killProcessTree(process RunningProcess, group int) { requestProcessTermination(process, group) }

func processGroupNeedsGrace(int) bool { return false }
