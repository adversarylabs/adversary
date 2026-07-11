//go:build !windows

package adversary

import (
	"os"
	"os/exec"
	"syscall"
)

func configureProcess(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

func supervisedProcessGroup(cmd *exec.Cmd) int {
	if cmd.Process == nil || cmd.Process.Pid <= 1 || cmd.Process.Pid == syscall.Getpgrp() || cmd.Process.Pid == os.Getpid() {
		return 0
	}
	return cmd.Process.Pid
}

func requestProcessTermination(_ *exec.Cmd, group int) {
	if group > 1 {
		_ = syscall.Kill(-group, syscall.SIGTERM)
	}
}

func killProcessTree(_ *exec.Cmd, group int) {
	if group > 1 {
		_ = syscall.Kill(-group, syscall.SIGKILL)
	}
}
