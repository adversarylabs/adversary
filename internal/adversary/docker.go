package adversary

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"sort"
)

type ContainerExecutor interface {
	Run(ctx context.Context, spec ContainerSpec) (ContainerResult, error)
}

type ImageBuilder interface {
	Build(ctx context.Context, spec BuildSpec) (BuildResult, error)
}

type DockerExecutor struct {
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
}

type DockerBuilder struct {
	Stdout io.Writer
	Stderr io.Writer
}

type ContainerSpec struct {
	Image           string
	Command         []string
	RepoPath        string
	RunDir          string
	NetworkDisabled bool
	Env             map[string]string
	Shell           bool
}

type BuildSpec struct {
	Image   string
	Context string
}

type BuildResult struct {
	ExitCode int
}

type ContainerResult struct {
	ExitCode int
}

func (b DockerBuilder) Build(ctx context.Context, spec BuildSpec) (BuildResult, error) {
	args := dockerBuildArgs(spec)

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = b.Stdout
	cmd.Stderr = b.Stderr
	if err := cmd.Run(); err != nil {
		return BuildResult{ExitCode: exitCode(err)}, fmt.Errorf("image build failed: %w", err)
	}
	return BuildResult{ExitCode: 0}, nil
}

func (e DockerExecutor) Run(ctx context.Context, spec ContainerSpec) (ContainerResult, error) {
	args := dockerRunArgs(spec)

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = e.Stdout
	cmd.Stderr = e.Stderr
	cmd.Stdin = e.Stdin
	if err := cmd.Run(); err != nil {
		return ContainerResult{ExitCode: exitCode(err)}, fmt.Errorf("container execution failed: %w", err)
	}
	return ContainerResult{ExitCode: 0}, nil
}

func dockerBuildArgs(spec BuildSpec) []string {
	return []string{"build", "-t", spec.Image, spec.Context}
}

func dockerRunArgs(spec ContainerSpec) []string {
	args := []string{
		"run",
		"--rm",
	}
	if spec.Shell {
		args = append(args, "-it")
	}
	args = append(args,
		"-v", fmt.Sprintf("%s:/workspace:ro", spec.RepoPath),
		"-v", fmt.Sprintf("%s/input.json:/adversary/input.json:ro", spec.RunDir),
		"-v", fmt.Sprintf("%s/output.json:/adversary/output.json", spec.RunDir),
	)
	if spec.NetworkDisabled {
		args = append(args, "--network", "none")
	}
	for _, key := range sortedEnvKeys(spec.Env) {
		args = append(args, "-e", key+"="+spec.Env[key])
	}
	args = append(args, spec.Image)
	if spec.Shell {
		args = append(args, "/bin/sh")
	} else {
		args = append(args, spec.Command...)
	}
	return args
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
