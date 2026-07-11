//go:build windows

package adversary

import (
	"os/exec"
)

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
