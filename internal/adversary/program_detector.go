package adversary

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/pkg/detection"
)

const maxDetectionOutputBytes int64 = 1 << 20

type DetectOptions struct {
	AdversaryRef             string
	RepoPath                 string
	ReviewContext            detection.Context
	AllowUnsafeHostExecution bool
	Timeout                  time.Duration
	ReferenceIdentity        string
}

type DetectorPolicyError struct {
	Err                 error
	DeclarativeFallback bool
}

func (e *DetectorPolicyError) Error() string {
	return fmt.Sprintf("programmatic detector policy: %v", e.Err)
}
func (e *DetectorPolicyError) Unwrap() error { return e.Err }

// Detect executes a programmatic detector through the same executor, trust
// policy, permissions, capabilities, immutable artifact, and materialization
// boundaries used for reviews.
func (r Runner) Detect(ctx context.Context, opts DetectOptions) (detection.Result, error) {
	files := r.runtimeFiles()
	executor := r.Executor
	if executor == nil {
		executor = HostExecutor{Stdout: r.Stderr, Stderr: r.Stderr, Stdin: r.Stdin}
	}
	explicitLocal, err := r.isExplicitLocalAdversaryPath(opts.AdversaryRef)
	if err != nil {
		return detection.Result{}, err
	}
	var resolved ResolvedAdversary
	if r.Resolver != nil {
		resolved, err = ResolveReferenceWithRuntime(opts.AdversaryRef, *r.Resolver, files)
	} else if r.RequireInjectedResolver {
		return detection.Result{}, fmt.Errorf("injected resolver is required")
	} else {
		resolved, err = ResolveReference(opts.AdversaryRef)
	}
	if err != nil {
		return detection.Result{}, err
	}
	if !resolved.LocalDir || resolved.Manifest == nil {
		return detection.Result{}, fmt.Errorf("adversary %q is not installed locally", opts.AdversaryRef)
	}
	if resolved.Manifest.Detection.Entrypoint == "" {
		return EvaluateDeclarativeDetection(*resolved.Manifest, opts.ReviewContext), nil
	}
	if resolved.StoreBacked {
		repository := r.Repository
		if repository == nil {
			return detection.Result{}, fmt.Errorf("repository dependency is required for stored detector")
		}
		lease, err := repository.LeaseMaterialized(resolved.StoreRecord)
		if err != nil {
			return detection.Result{}, err
		}
		defer lease.Close()
		resolved.ExecutionPath, resolved.BuildContext, resolved.StorePath = lease.Path, lease.Path, lease.Path
	}
	publisherRef := opts.AdversaryRef
	if opts.ReferenceIdentity != "" {
		resolved.CanonicalReference = opts.ReferenceIdentity
		publisherRef = opts.ReferenceIdentity
	}
	publisher, err := classifyPublisher(publisherRef, resolved, explicitLocal)
	if err != nil {
		return detection.Result{}, err
	}
	trustPolicy := r.TrustPolicy
	if trustPolicy == nil {
		policy := DefaultPublisherTrustPolicy()
		trustPolicy = policy
	}
	trust := trustPolicy.Evaluate(publisher)
	resolved.Publisher = trust.Publisher.Name
	permissionPolicy := r.PermissionPolicy
	if permissionPolicy == nil {
		permissionPolicy = AllowRequestedPermissionsPolicy{}
	}
	requirements := permissionRequirements(resolved, RunOptions{})
	if _, err := DecideExecutionPolicy(ExecutionPolicyRequest{Trust: trust, Requested: requirements.Requested, Required: requirements.Required, Allowed: permissionPolicy.Allowed(trust), Backend: executor.Backend(), Capabilities: executor.Capabilities(), AllowUnsafeHostExecution: opts.AllowUnsafeHostExecution}); err != nil {
		fallback := trust.Trust == UnknownPublisherTrust && executor.Backend() == HostExecutorBackend && !opts.AllowUnsafeHostExecution && strings.Contains(err.Error(), "cannot execute with HostExecutor")
		return detection.Result{}, &DetectorPolicyError{Err: err, DeclarativeFallback: fallback}
	}

	repoPath := opts.RepoPath
	if repoPath == "" {
		repoPath = opts.ReviewContext.RepositoryRoot
	}
	repoPath, err = files.Abs(repoPath)
	if err != nil {
		return detection.Result{}, err
	}
	runDir, err := files.MkdirTemp(r.TempDir, "adversary-detect-*")
	if err != nil {
		return detection.Result{}, err
	}
	removeAll := r.RemoveAll
	if removeAll == nil {
		removeAll = files.RemoveAll
	}
	defer removeAll(runDir)

	detectorContext := opts.ReviewContext
	detectorContext.RepositoryRoot = "/workspace"
	inputData, err := json.MarshalIndent(detectorContext, "", "  ")
	if err != nil {
		return detection.Result{}, err
	}
	inputPath := filepath.Join(runDir, "detection-input.json")
	outputPath := filepath.Join(runDir, "detection-output.json")
	if err := files.WriteFile(inputPath, inputData, 0644); err != nil {
		return detection.Result{}, err
	}
	if err := files.WriteFile(outputPath, nil, 0644); err != nil {
		return detection.Result{}, err
	}
	entrypoint := filepath.Join(resolved.ExecutionPath, filepath.FromSlash(resolved.Manifest.Detection.Entrypoint))
	resolved.Command = []string{"node", entrypoint}
	config := NewRunConfig(resolved, repoPath, runDir, RunOptions{})
	delete(config.Env, "ADVERSARY_INPUT")
	delete(config.Env, "ADVERSARY_OUTPUT")
	config.Env["ADVERSARY_DETECTION_INPUT"] = inputPath
	config.Env["ADVERSARY_DETECTION_OUTPUT"] = outputPath

	detectCtx := ctx
	cancel := func() {}
	if opts.Timeout > 0 {
		detectCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
	}
	_, err = executor.Run(detectCtx, config.RuntimeSpec())
	cancel()
	if err != nil {
		return detection.Result{}, fmt.Errorf("programmatic detector execution: %w", err)
	}
	return decodeDetectionResult(files, outputPath)
}

func decodeDetectionResult(files RuntimeFiles, path string) (detection.Result, error) {
	file, err := files.Open(path)
	if err != nil {
		return detection.Result{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxDetectionOutputBytes+1))
	if err != nil {
		return detection.Result{}, err
	}
	if int64(len(data)) > maxDetectionOutputBytes {
		return detection.Result{}, fmt.Errorf("detection output exceeds %d bytes", maxDetectionOutputBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var result detection.Result
	if err := decoder.Decode(&result); err != nil {
		return detection.Result{}, fmt.Errorf("decode detection result: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return detection.Result{}, fmt.Errorf("detection output must contain one JSON document")
	}
	if err := result.Validate(); err != nil {
		return detection.Result{}, err
	}
	result.Normalize()
	return result, nil
}
