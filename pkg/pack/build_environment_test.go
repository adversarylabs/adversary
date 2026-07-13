package pack

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// BuildProject is the test-only ambient adapter. Production callers must
// compose BuildProjectWithEnvironment explicitly.
func BuildProject(ctx context.Context, opts BuildOptions) error {
	npm, npmErr := exec.LookPath("npm")
	node, nodeErr := exec.LookPath("node")
	if npm != "" && nodeErr != nil {
		adjacent := filepath.Join(filepath.Dir(npm), "node")
		if info, err := os.Stat(adjacent); err == nil && !info.IsDir() {
			node, nodeErr = adjacent, nil
		}
	}
	docker, dockerErr := exec.LookPath("docker")
	environment := BuildEnvironment{NPM: npm, NPMError: npmErr, Node: node, NodeError: nodeErr, Docker: docker, DockerError: dockerErr, Environment: os.Environ(), Run: func(ctx context.Context, executable string, args []string, dir string, env []string, stdout, stderr io.Writer, capture bool) ([]byte, error) {
		cmd := exec.CommandContext(ctx, executable, args...)
		cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = dir, env, stdout, stderr
		if capture {
			return cmd.Output()
		}
		return nil, cmd.Run()
	}}
	return BuildProjectWithEnvironment(ctx, opts, environment)
}
