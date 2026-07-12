package adversary

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// findNode preserves the original test helper while production callers must
// supply all process environment and path dependencies explicitly.
func findNode(version string) (string, error) {
	home, _ := os.UserHomeDir()
	environment := NewProcessEnvironment(os.Environ(), runtime.GOOS == "windows")
	validate := func(path string) error { return ValidateExecutable(path, os.Getenv("PATHEXT")) }
	resolveExplicit := func(path string) (string, error) {
		if !filepath.IsAbs(path) {
			return "", fmt.Errorf("executable path %q is not absolute", path)
		}
		if err := validate(path); err != nil {
			return "", err
		}
		return filepath.EvalSymlinks(path)
	}
	resolvePATH := func(path string) (string, error) {
		canonical, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", err
		}
		if err := validate(canonical); err != nil {
			return "", err
		}
		return canonical, nil
	}
	lookPath := func(file string) (string, error) {
		return environment.LookPath(file, resolvePATH)
	}
	return (NodeResolver{LookupEnv: environment.Lookup, LookPath: lookPath, HomeDir: home, Glob: filepath.Glob, ResolveExecutable: resolveExplicit, Environment: environment, Output: ExecProcessOutputRunner{}}).Find(context.Background(), version)
}

func isExplicitLocalAdversaryPath(ref string) (bool, error) {
	home, _ := os.UserHomeDir()
	data, _ := resolverDataRoot()
	return (Runner{HomeDir: home, DataRoot: data}).isExplicitLocalAdversaryPath(ref)
}

func artifactStorageRoots() ([]string, error) {
	home, _ := os.UserHomeDir()
	data, _ := resolverDataRoot()
	return (Runner{HomeDir: home, DataRoot: data}).artifactStorageRoots()
}

func systemHostExecutorForTest(stdin io.Reader, stdout, stderr io.Writer) HostExecutor {
	home, _ := os.UserHomeDir()
	environment := NewProcessEnvironment(os.Environ(), runtime.GOOS == "windows")
	pathext, _ := environment.Lookup("PATHEXT")
	resolveExplicit := func(path string) (string, error) {
		if !filepath.IsAbs(path) {
			return "", fmt.Errorf("executable path %q is not absolute", path)
		}
		if err := ValidateExecutable(path, pathext); err != nil {
			return "", err
		}
		return filepath.EvalSymlinks(path)
	}
	resolvePATH := func(path string) (string, error) {
		canonical, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", err
		}
		if err := ValidateExecutable(canonical, pathext); err != nil {
			return "", err
		}
		return canonical, nil
	}
	lookPath := func(file string) (string, error) { return environment.LookPath(file, resolvePATH) }
	output := ExecProcessOutputRunner{}
	resolver := NodeResolver{LookupEnv: environment.Lookup, LookPath: lookPath, HomeDir: home, Glob: filepath.Glob, ResolveExecutable: resolveExplicit, Environment: environment, Output: output}
	return HostExecutor{Stdin: stdin, Stdout: stdout, Stderr: stderr, Environment: environment, ResolveExecutable: func(name string) (string, error) {
		if filepath.IsAbs(name) {
			return resolveExplicit(name)
		}
		return lookPath(name)
	}, FindNode: resolver.Find, Launcher: ExecProcessLauncher{}, Timer: NewRuntimeTimer}
}
