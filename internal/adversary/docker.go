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
	"strconv"
	"strings"
	"time"

	semver "github.com/Masterminds/semver/v3"
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

// UnsupportedFeatureError lets callers distinguish an unavailable platform
// guarantee from an execution failure.
type UnsupportedFeatureError struct{ Platform, Feature string }

func (e *UnsupportedFeatureError) Error() string {
	return fmt.Sprintf("host execution cannot enforce %s on %s", e.Feature, e.Platform)
}

// ChildExitError preserves the child status while retaining the cancellation or
// operating-system cause for process-edge exit classification.
type ChildExitError struct {
	ExitCode int
	Err      error
}

func (e *ChildExitError) Error() string {
	return fmt.Sprintf("host execution failed (child exit %d): %v", e.ExitCode, e.Err)
}
func (e *ChildExitError) Unwrap() error { return e.Err }

func (e HostExecutor) Run(ctx context.Context, spec ContainerSpec) (ContainerResult, error) {
	if spec.RuntimeName == "" && spec.Image != "" && !strings.HasPrefix(spec.Image, "host:") {
		return ContainerResult{ExitCode: -1, Kind: "Process"}, &UnsupportedFeatureError{Platform: runtime.GOOS, Feature: "container image runtime execution"}
	}
	if spec.NetworkDisabled {
		return ContainerResult{ExitCode: -1, Kind: "Process"}, &UnsupportedFeatureError{Platform: runtime.GOOS, Feature: "disabled network access"}
	}
	command := spec.Command
	if spec.Shell {
		var err error
		command, err = platformShell()
		if err != nil {
			return ContainerResult{ExitCode: -1, Kind: "Process"}, err
		}
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
	cmd := exec.Command(command[0], command[1:]...)
	configureProcess(cmd)
	cmd.Dir = spec.AdversaryPath
	cmd.Stdout = e.Stdout
	cmd.Stderr = e.Stderr
	cmd.Stdin = e.Stdin
	cmd.Env = os.Environ()
	for _, key := range sortedEnvKeys(spec.Env) {
		cmd.Env = append(cmd.Env, key+"="+spec.Env[key])
	}
	if err := cmd.Start(); err != nil {
		return ContainerResult{ExitCode: -1, Kind: "Process"}, &ChildExitError{ExitCode: -1, Err: err}
	}
	group := supervisedProcessGroup(cmd)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			code := exitCode(err)
			return ContainerResult{ExitCode: code, Kind: "Process"}, &ChildExitError{ExitCode: code, Err: err}
		}
		return ContainerResult{ExitCode: 0, Kind: "Process"}, nil
	case <-ctx.Done():
		requestProcessTermination(cmd, group)
		timer := time.NewTimer(750 * time.Millisecond)
		var err error
		reaped := false
		select {
		case err = <-done:
			reaped = true
			<-timer.C
		case <-timer.C:
		}
		killProcessTree(cmd, group)
		if !reaped {
			err = <-done
		}
		code := exitCode(err)
		return ContainerResult{ExitCode: code, Kind: "Process"}, &ChildExitError{ExitCode: code, Err: ctx.Err()}
	}
}

func findNode(version string) (string, error) {
	constraint, err := nodeConstraint(version)
	if err != nil {
		return "", fmt.Errorf("invalid Node.js runtime requirement %q: %w", version, err)
	}
	if override := strings.TrimSpace(os.Getenv("ADVERSARY_NODE_PATH")); override != "" {
		override, err = filepath.Abs(override)
		if err != nil {
			return "", fmt.Errorf("resolve ADVERSARY_NODE_PATH: %w", err)
		}
		if err := validateExecutable(override); err != nil {
			return "", fmt.Errorf("ADVERSARY_NODE_PATH %q: %w", override, err)
		}
		if err := nodeSatisfies(override, constraint); err != nil {
			return "", fmt.Errorf("ADVERSARY_NODE_PATH %q: %w", override, err)
		}
		return override, nil
	}
	if path, err := exec.LookPath("node"); err == nil {
		if validateExecutable(path) == nil && nodeSatisfies(path, constraint) == nil {
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
		if validateExecutable(candidate) == nil && nodeSatisfies(candidate, constraint) == nil {
			return candidate, nil
		}
	}
	if version != "" {
		return "", fmt.Errorf("host execution failed: no user-managed Node.js executable satisfies %q; install Node.js or set ADVERSARY_NODE_PATH", version)
	}
	return "", fmt.Errorf("host execution failed: Node.js was not found; install Node.js or set ADVERSARY_NODE_PATH")
}

func nodeSatisfies(path string, constraint *semver.Constraints) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("query Node.js version: %w", ctx.Err())
		}
		return fmt.Errorf("query Node.js version: %w", err)
	}
	got, err := semver.NewVersion(strings.TrimSpace(string(out)))
	if err != nil {
		return fmt.Errorf("parse Node.js version output %q: %w", strings.TrimSpace(string(out)), err)
	}
	if constraint != nil && !constraint.Check(got) {
		return fmt.Errorf("Node.js %s does not satisfy runtime requirement %s", got, constraint)
	}
	return nil
}

func nodeConstraint(requirement string) (*semver.Constraints, error) {
	v := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(requirement), "node@"), "v")
	if v == "" {
		return nil, nil
	}
	parts := strings.Split(v, ".")
	if len(parts) <= 2 && strings.IndexAny(v, "<>=~^*xX ,|") < 0 {
		if len(parts) == 1 {
			n, err := strconv.ParseUint(parts[0], 10, 64)
			if err != nil {
				return nil, err
			}
			v = ">=" + v + ".0.0, <" + fmt.Sprint(n+1) + ".0.0"
		} else {
			n, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				return nil, err
			}
			v = ">=" + v + ".0, <" + parts[0] + "." + fmt.Sprint(n+1) + ".0"
		}
	}
	return semver.NewConstraint(v)
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
