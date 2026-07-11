//go:build !windows

package adversary

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func PlatformShell(lookPath func(string) (string, error)) ([]string, error) {
	path, err := lookPath("sh")
	if err != nil {
		return nil, fmt.Errorf("host shell is unavailable: %w", err)
	}
	return []string{path}, nil
}

func ValidateExecutable(path, _ string) error {
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

func supervisedProcessGroup(process RunningProcess) int {
	pid := process.PID()
	if pid <= 1 || pid == syscall.Getpgrp() || pid == os.Getpid() {
		return 0
	}
	return pid
}

func requestProcessTermination(process RunningProcess, group int) {
	if group > 1 {
		_ = syscall.Kill(-group, syscall.SIGTERM)
		return
	}
	_ = process.Kill()
}

func killProcessTree(process RunningProcess, group int) {
	if group > 1 {
		_ = syscall.Kill(-group, syscall.SIGKILL)
		return
	}
	_ = process.Kill()
}

func processGroupNeedsGrace(group int) bool { return group > 1 }
