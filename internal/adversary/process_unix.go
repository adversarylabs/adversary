//go:build !windows

package adversary

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func platformShell() ([]string, error) {
	path, err := exec.LookPath("sh")
	if err != nil {
		return nil, fmt.Errorf("host shell is unavailable: %w", err)
	}
	return []string{path}, nil
}

func validateExecutable(path string) error {
	info, err := executableFileInfo(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("not executable")
	}
	return nil
}

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
