package adversary

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/modelreview"
)

type brokerCallingExecutor struct {
	spec RuntimeSpec
}

func (*brokerCallingExecutor) Backend() ExecutorBackend           { return HostExecutorBackend }
func (*brokerCallingExecutor) Capabilities() ExecutorCapabilities { return ExecutorCapabilities{} }
func (e *brokerCallingExecutor) Run(_ context.Context, spec RuntimeSpec) (RuntimeResult, error) {
	e.spec = spec
	requestBody := modelreview.Request{
		ProtocolVersion: modelreview.ProtocolVersion,
		Prompt:          "Review this change.",
		Input:           json.RawMessage(`{"file":"main.go"}`),
		Schema:          json.RawMessage(`{"type":"object","required":["decision"],"properties":{"decision":{"const":"approve"}}}`),
		Budget:          modelreview.Budget{MaximumOutputTokens: 1000, TimeoutMS: 5000},
	}
	data, _ := json.Marshal(requestBody)
	request, err := http.NewRequest(http.MethodPost, spec.Env["ADVERSARY_MODEL_ENDPOINT"], bytes.NewReader(data))
	if err != nil {
		return RuntimeResult{}, err
	}
	request.Header.Set("authorization", "Bearer "+spec.Env["ADVERSARY_MODEL_TOKEN"])
	request.Header.Set("x-adversary-model-protocol", "1")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return RuntimeResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return RuntimeResult{}, &modelreview.ProviderError{Message: response.Status}
	}
	if err := os.WriteFile(filepath.Join(spec.RunDir, "output.json"), minimalEnvelope(), 0644); err != nil {
		return RuntimeResult{}, err
	}
	return RuntimeResult{ExitCode: 0, Kind: "Process"}, nil
}

func TestRunnerProvidesModelBrokerWithoutExposingProviderKey(t *testing.T) {
	project := writeRunnerProject(t, "permissions:\n  model: true\n")
	writeFile(t, filepath.Join(project, "index.js"), "")
	executor := &brokerCallingExecutor{}
	provider := &fixtureRunnerProvider{}
	var stderr bytes.Buffer
	err := (Runner{
		Stdout:   &bytes.Buffer{},
		Stderr:   &stderr,
		Executor: executor,
		ModelBrokerFactory: func() (modelreview.Broker, error) {
			return modelreview.Broker{Provider: provider}, nil
		},
	}).Run(context.Background(), RunOptions{
		AdversaryRef: project,
		RepoPath:     t.TempDir(),
		Format:       "json",
		Verbose:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(provider.requests) != 1 {
		t.Fatalf("provider calls = %d", len(provider.requests))
	}
	if executor.spec.Env["ADVERSARY_MODEL_ENDPOINT"] == "" || executor.spec.Env["ADVERSARY_MODEL_TOKEN"] == "" {
		t.Fatalf("broker environment = %#v", executor.spec.Env)
	}
	if strings.Contains(stderr.String(), executor.spec.Env["ADVERSARY_MODEL_TOKEN"]) || !strings.Contains(stderr.String(), "ADVERSARY_MODEL_TOKEN=<redacted>") {
		t.Fatalf("verbose diagnostics leaked broker token:\n%s", stderr.String())
	}
	for _, key := range []string{modelreview.OpenAIKeyEnv, modelreview.AnthropicKeyEnv} {
		if !slices.Contains(executor.spec.EnvironmentDeny, key) {
			t.Fatalf("provider credential %s is not denied at the process boundary", key)
		}
	}
}

func TestRunnerFailsBeforeLaunchWhenModelBrokerIsUnavailable(t *testing.T) {
	project := writeRunnerProject(t, "permissions:\n  model: true\n")
	writeFile(t, filepath.Join(project, "index.js"), "")
	executor := &brokerCallingExecutor{}
	err := (Runner{
		Stdout:   &bytes.Buffer{},
		Stderr:   &bytes.Buffer{},
		Executor: executor,
	}).Run(context.Background(), RunOptions{
		AdversaryRef: project,
		RepoPath:     t.TempDir(),
		Format:       "json",
	})
	if err == nil || !strings.Contains(err.Error(), "model broker dependency is required") {
		t.Fatalf("error = %v", err)
	}
	if executor.spec.Env != nil {
		t.Fatal("executor launched without a model broker")
	}
}

func TestRuntimeSpecAlwaysDeniesCLIModelProviderCredentials(t *testing.T) {
	spec := NewRunConfig(ResolvedAdversary{}, t.TempDir(), t.TempDir(), RunOptions{}).RuntimeSpec()
	for _, key := range []string{modelreview.OpenAIKeyEnv, modelreview.AnthropicKeyEnv} {
		if !slices.Contains(spec.EnvironmentDeny, key) {
			t.Fatalf("provider credential %s is not denied without permissions.model", key)
		}
	}
}

type fixtureRunnerProvider struct {
	requests []modelreview.Request
}

func (*fixtureRunnerProvider) Name() string  { return "fixture" }
func (*fixtureRunnerProvider) Model() string { return "reviewer-v1" }
func (p *fixtureRunnerProvider) Review(_ context.Context, request modelreview.Request) (modelreview.Result, error) {
	p.requests = append(p.requests, request)
	return modelreview.Result{Output: json.RawMessage(`{"decision":"approve"}`)}, nil
}
