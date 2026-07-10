package adversary

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
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
	RuntimeName     string
	RuntimeVersion  string
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
	if spec.NetworkDisabled {
		return ContainerResult{ExitCode: -1, Kind: "Process"}, fmt.Errorf("host execution cannot enforce disabled network access")
	}
	command := spec.Command
	if spec.Shell {
		command = []string{"/bin/sh"}
	}
	if len(command) == 0 {
		return ContainerResult{ExitCode: -1, Kind: "Process"}, fmt.Errorf("host execution command is empty")
	}
	if command[0] == "node" {
		node, err := findNode(spec.RuntimeVersion)
		if err != nil {
			return ContainerResult{ExitCode: -1, Kind: "Process"}, err
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

func findNode(version string) (string, error) {
	version = normalizeNodeVersion(version)
	if override := strings.TrimSpace(os.Getenv("ADVERSARY_NODE_PATH")); override != "" {
		return override, nil
	}
	if path, ok := managedNodePath(version); ok {
		return path, nil
	}
	if path, err := exec.LookPath("node"); err == nil {
		if version == "" || nodeMatchesVersion(path, version) {
			return path, nil
		}
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
			if version == "" || nodeMatchesVersion(candidate, version) {
				return candidate, nil
			}
		}
	}
	if version != "" {
		return "", fmt.Errorf("host execution failed: Node.js %s was not found; install a managed runtime or set ADVERSARY_NODE_PATH", version)
	}
	return "", fmt.Errorf("host execution failed: Node.js was not found; install a managed runtime or set ADVERSARY_NODE_PATH")
}

func managedNodePath(version string) (string, bool) {
	if version == "" {
		return "", false
	}
	root, err := adversaryDataDir()
	if err != nil {
		return "", false
	}
	path := filepath.Join(root, "runtimes", "node", version, runtime.GOOS+"-"+runtime.GOARCH, "bin", "node")
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return path, true
	}
	return "", false
}

func adversaryDataDir() (string, error) {
	if override := strings.TrimSpace(os.Getenv("ADVERSARY_DATA_DIR")); override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Adversary"), nil
	case "linux":
		if xdg := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); xdg != "" {
			return filepath.Join(xdg, "adversary"), nil
		}
		return filepath.Join(home, ".local", "share", "adversary"), nil
	default:
		return filepath.Join(home, ".adversary"), nil
	}
}

func nodeMatchesVersion(path, version string) bool {
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(string(out), "v"))
	if got == version || strings.HasPrefix(got, version+".") {
		return true
	}
	return false
}

func normalizeNodeVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "node@")
	version = strings.TrimPrefix(version, "v")
	return version
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
