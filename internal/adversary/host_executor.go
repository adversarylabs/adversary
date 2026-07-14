package adversary

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	semver "github.com/Masterminds/semver/v3"
)

type RuntimeExecutor interface {
	Run(ctx context.Context, spec RuntimeSpec) (RuntimeResult, error)
}

type HostExecutor struct {
	Stdout            io.Writer
	Stderr            io.Writer
	Stdin             io.Reader
	Environment       ProcessEnvironment
	ResolveExecutable func(string) (string, error)
	FindNode          func(context.Context, string) (string, error)
	Shell             func() ([]string, error)
	Launcher          ProcessLauncher
	Timer             func(time.Duration) RuntimeTimer
}

type RuntimeTimer interface {
	C() <-chan time.Time
	Stop() bool
}

type RuntimeSpec struct {
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

type RuntimeResult struct {
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

func (e HostExecutor) Run(ctx context.Context, spec RuntimeSpec) (RuntimeResult, error) {
	if spec.RuntimeName == "" && spec.Image != "" && !strings.HasPrefix(spec.Image, "host:") {
		return RuntimeResult{ExitCode: -1, Kind: "Process"}, &UnsupportedFeatureError{Platform: runtime.GOOS, Feature: "container image runtime execution"}
	}
	if spec.NetworkDisabled {
		return RuntimeResult{ExitCode: -1, Kind: "Process"}, &UnsupportedFeatureError{Platform: runtime.GOOS, Feature: "disabled network access"}
	}
	command := spec.Command
	if spec.Shell {
		var err error
		if e.Shell == nil {
			return RuntimeResult{ExitCode: -1, Kind: "Process"}, fmt.Errorf("host shell dependency is required")
		}
		command, err = e.Shell()
		if err != nil {
			return RuntimeResult{ExitCode: -1, Kind: "Process"}, err
		}
	}
	if len(command) == 0 {
		return RuntimeResult{ExitCode: -1, Kind: "Process"}, fmt.Errorf("host execution command is empty")
	}
	if command[0] == "node" {
		find := e.FindNode
		if find == nil {
			return RuntimeResult{ExitCode: -1, Kind: "Process"}, fmt.Errorf("host execution Node.js resolver dependency is required")
		}
		node, err := find(ctx, spec.RuntimeVersion)
		if err != nil {
			return RuntimeResult{ExitCode: -1, Kind: "Process"}, err
		}
		command = append([]string{node}, command[1:]...)
	}
	resolve := e.ResolveExecutable
	if resolve == nil {
		return RuntimeResult{ExitCode: -1, Kind: "Process"}, fmt.Errorf("host execution executable resolver dependency is required")
	}
	executable := command[0]
	if !filepath.IsAbs(executable) && strings.ContainsAny(executable, `/\\`) {
		executable = filepath.Join(spec.AdversaryPath, executable)
	}
	executable, err := resolve(executable)
	if err != nil {
		return RuntimeResult{ExitCode: -1, Kind: "Process"}, fmt.Errorf("resolve host executable %q: %w", command[0], err)
	}
	if !filepath.IsAbs(executable) {
		return RuntimeResult{ExitCode: -1, Kind: "Process"}, fmt.Errorf("resolved host executable %q is not absolute", executable)
	}
	if e.Launcher == nil {
		return RuntimeResult{ExitCode: -1, Kind: "Process"}, fmt.Errorf("host execution process launcher dependency is required")
	}
	if err := ctx.Err(); err != nil {
		return RuntimeResult{ExitCode: -1, Kind: "Process"}, &ChildExitError{ExitCode: -1, Err: err}
	}
	process, err := e.Launcher.Start(ProcessLaunchOptions{Path: executable, Args: command[1:], Dir: spec.AdversaryPath, Stdout: e.Stdout, Stderr: e.Stderr, Stdin: e.Stdin, Env: e.Environment.Entries(spec.Env)})
	if err != nil {
		return RuntimeResult{ExitCode: -1, Kind: "Process"}, &ChildExitError{ExitCode: -1, Err: err}
	}
	group := supervisedProcessGroup(process)
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			code := exitCode(err)
			return RuntimeResult{ExitCode: code, Kind: "Process"}, &ChildExitError{ExitCode: code, Err: err}
		}
		return RuntimeResult{ExitCode: 0, Kind: "Process"}, nil
	case <-ctx.Done():
		requestProcessTermination(process, group)
		var waitErr error
		reaped := false
		if processGroupNeedsGrace(group) {
			if e.Timer == nil {
				killProcessTree(process, group)
				waitErr = <-done
				return RuntimeResult{ExitCode: exitCode(waitErr), Kind: "Process"}, fmt.Errorf("host execution grace timer dependency is required")
			}
			timer := e.Timer(750 * time.Millisecond)
			for timer != nil {
				select {
				case waitErr = <-done:
					reaped = true
					done = nil
				case <-timer.C():
					timer = nil
				}
			}
		} else {
			waitErr = <-done
			reaped = true
		}
		killProcessTree(process, group)
		if !reaped {
			waitErr = <-done
		}
		code := exitCode(waitErr)
		return RuntimeResult{ExitCode: code, Kind: "Process"}, &ChildExitError{ExitCode: code, Err: ctx.Err()}
	}
}

type NodeResolver struct {
	LookupEnv         func(string) (string, bool)
	LookPath          func(string) (string, error)
	HomeDir           string
	Glob              func(string) ([]string, error)
	ResolveExecutable func(string) (string, error)
	Environment       ProcessEnvironment
	Output            ProcessOutputRunner
}

func (r NodeResolver) Find(ctx context.Context, version string) (string, error) {
	if r.LookupEnv == nil || r.LookPath == nil || r.HomeDir == "" || r.Glob == nil || r.ResolveExecutable == nil || r.Output == nil {
		return "", fmt.Errorf("Node.js resolver dependencies are incomplete")
	}
	constraint, err := nodeConstraint(version)
	if err != nil {
		return "", fmt.Errorf("invalid Node.js runtime requirement %q: %w", version, err)
	}
	if override, ok := r.LookupEnv("ADVERSARY_NODE_PATH"); ok && strings.TrimSpace(override) != "" {
		requested := strings.TrimSpace(override)
		override, err = r.ResolveExecutable(requested)
		if err != nil {
			return "", fmt.Errorf("ADVERSARY_NODE_PATH %q: %w", requested, err)
		}
		if err := r.nodeSatisfies(ctx, override, constraint); err != nil {
			return "", fmt.Errorf("ADVERSARY_NODE_PATH %q: %w", override, err)
		}
		return override, nil
	}
	if path, pathErr := r.LookPath("node"); pathErr == nil {
		if r.nodeSatisfies(ctx, path, constraint) == nil {
			return path, nil
		}
	} else if errors.Is(pathErr, ErrUnsafeCapturedPATH) {
		return "", fmt.Errorf("resolve Node.js from captured PATH: %w", pathErr)
	}
	home := r.HomeDir
	matches, _ := r.Glob(filepath.Join(home, ".nvm", "versions", "node", "*", "bin", "node"))
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	candidates := append(matches,
		filepath.Join(home, ".volta", "bin", "node"),
		filepath.Join(home, ".asdf", "shims", "node"),
	)
	for _, candidate := range candidates {
		resolved, resolveErr := r.ResolveExecutable(candidate)
		if resolveErr == nil && r.nodeSatisfies(ctx, resolved, constraint) == nil {
			return resolved, nil
		}
	}
	if version != "" {
		return "", fmt.Errorf("host execution failed: no user-managed Node.js executable satisfies %q; install Node.js or set ADVERSARY_NODE_PATH", version)
	}
	return "", fmt.Errorf("host execution failed: Node.js was not found; install Node.js or set ADVERSARY_NODE_PATH")
}

func (r NodeResolver) nodeSatisfies(parent context.Context, path string, constraint *semver.Constraints) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	out, stderr, err := r.Output.RunOutput(ctx, ProcessOutputOptions{Path: path, Args: []string{"--version"}, Env: r.Environment.Entries(nil)})
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("query Node.js version: %w", ctx.Err())
		}
		if detail := strings.TrimSpace(string(stderr)); detail != "" {
			return fmt.Errorf("query Node.js version: %s", detail)
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
	var exitErr interface{ ExitCode() int }
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
