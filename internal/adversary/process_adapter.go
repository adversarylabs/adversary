package adversary

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"time"
)

// ProcessLaunchOptions is the complete process state supplied by runtime
// policy. Path must already be an absolute, validated executable path; the
// concrete adapter never consults the process-wide PATH.
type ProcessLaunchOptions struct {
	Path           string
	Args           []string
	Dir            string
	Env            []string
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

// RunningProcess is the narrow lifecycle surface required by process-group
// supervision.
type RunningProcess interface {
	PID() int
	Wait() error
	Kill() error
}

type ProcessLauncher interface {
	Start(ProcessLaunchOptions) (RunningProcess, error)
}

// ExecProcessLauncher is the concrete os/exec adapter composed by cmd. All
// path and environment policy remains outside this adapter.
type ExecProcessLauncher struct{}

func (ExecProcessLauncher) Start(opts ProcessLaunchOptions) (RunningProcess, error) {
	if !filepath.IsAbs(opts.Path) {
		return nil, fmt.Errorf("process executable path %q is not absolute", opts.Path)
	}
	cmd := exec.Command(opts.Path, opts.Args...)
	configureProcess(cmd)
	cmd.Dir = opts.Dir
	cmd.Env = append([]string(nil), opts.Env...)
	cmd.Stdin = opts.Stdin
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return execRunningProcess{cmd: cmd}, nil
}

type execRunningProcess struct{ cmd *exec.Cmd }

func (p execRunningProcess) PID() int {
	if p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}
func (p execRunningProcess) Wait() error { return p.cmd.Wait() }
func (p execRunningProcess) Kill() error {
	if p.cmd.Process == nil {
		return nil
	}
	return p.cmd.Process.Kill()
}

type ProcessOutputOptions struct {
	Path string
	Args []string
	Dir  string
	Env  []string
}

type ProcessOutputRunner interface {
	RunOutput(context.Context, ProcessOutputOptions) (stdout, stderr []byte, err error)
}

// ExecProcessOutputRunner is the concrete adapter for helper commands such as
// Git queries and Node version probes.
type ExecProcessOutputRunner struct{}

func (ExecProcessOutputRunner) RunOutput(ctx context.Context, opts ProcessOutputOptions) ([]byte, []byte, error) {
	if !filepath.IsAbs(opts.Path) {
		return nil, nil, fmt.Errorf("process executable path %q is not absolute", opts.Path)
	}
	cmd := exec.CommandContext(ctx, opts.Path, opts.Args...)
	cmd.Dir = opts.Dir
	cmd.Env = append([]string(nil), opts.Env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

type systemRuntimeTimer struct{ *time.Timer }

func (t systemRuntimeTimer) C() <-chan time.Time { return t.Timer.C }

func NewRuntimeTimer(duration time.Duration) RuntimeTimer {
	return systemRuntimeTimer{Timer: time.NewTimer(duration)}
}
