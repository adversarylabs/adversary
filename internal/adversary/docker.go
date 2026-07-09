package adversary

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

type ContainerExecutor interface {
	Run(ctx context.Context, spec ContainerSpec) (ContainerResult, error)
}

type HostExecutor struct {
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
}

type ContainerSpec struct {
	Image           string
	Command         []string
	RepoPath        string
	RunDir          string
	AdversaryPath   string
	NetworkDisabled bool
	Env             map[string]string
	Shell           bool
}

type ContainerResult struct {
	ExitCode int
	Kind     string
}

func (e HostExecutor) Run(ctx context.Context, spec ContainerSpec) (ContainerResult, error) {
	command := spec.Command
	if spec.Shell {
		command = []string{"/bin/sh"}
	}
	if len(command) == 0 {
		return ContainerResult{ExitCode: -1, Kind: "Process"}, fmt.Errorf("host execution command is empty")
	}
	if command[0] == "node" {
		node, err := findNode()
		if err != nil {
			return ContainerResult{ExitCode: -1, Kind: "Process"}, fmt.Errorf("host execution failed: node was not found; install Node.js or ensure node is on PATH")
		}
		command = append([]string{node}, command[1:]...)
	}
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = spec.AdversaryPath
	cmd.Stdout = e.Stdout
	cmd.Stderr = e.Stderr
	cmd.Stdin = e.Stdin
	cmd.Env = os.Environ()
	for _, key := range sortedEnvKeys(spec.Env) {
		cmd.Env = append(cmd.Env, key+"="+spec.Env[key])
	}
	if err := cmd.Run(); err != nil {
		return ContainerResult{ExitCode: exitCode(err), Kind: "Process"}, fmt.Errorf("host execution failed: %w", err)
	}
	return ContainerResult{ExitCode: 0, Kind: "Process"}, nil
}

func findNode() (string, error) {
	if path, err := exec.LookPath("node"); err == nil {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	matches, _ := filepath.Glob(filepath.Join(home, ".nvm", "versions", "node", "*", "bin", "node"))
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	candidates := append(matches,
		filepath.Join(home, ".volta", "bin", "node"),
		filepath.Join(home, ".asdf", "shims", "node"),
	)
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", exec.ErrNotFound
}

func sortedEnvKeys(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func exitCode(err error) int {
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1
}
