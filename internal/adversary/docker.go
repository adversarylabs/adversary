package adversary

import (
	"context"
	"fmt"
	"io"
	"os/exec"
)

type ContainerExecutor interface {
	Run(ctx context.Context, spec ContainerSpec) error
}

type DockerExecutor struct {
	Stdout io.Writer
	Stderr io.Writer
}

type ContainerSpec struct {
	Image           string
	Command         []string
	RepoPath        string
	RunDir          string
	NetworkDisabled bool
}

func (e DockerExecutor) Run(ctx context.Context, spec ContainerSpec) error {
	args := []string{
		"run",
		"--rm",
		"-v", fmt.Sprintf("%s:/workspace:ro", spec.RepoPath),
		"-v", fmt.Sprintf("%s:/adversary", spec.RunDir),
	}
	if spec.NetworkDisabled {
		args = append(args, "--network", "none")
	}
	args = append(args, spec.Image)
	args = append(args, spec.Command...)

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = e.Stdout
	cmd.Stderr = e.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("container execution failed: %w", err)
	}
	return nil
}
