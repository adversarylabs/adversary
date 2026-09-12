package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/application"
)

type catalogModelRuntimeStub struct {
	config   application.ModelReviewConfig
	provider application.ModelReviewProvider
	err      error
}

func (s *catalogModelRuntimeStub) ModelReviewProvider(config application.ModelReviewConfig) (application.ModelReviewProvider, error) {
	s.config = config
	return s.provider, s.err
}

type catalogModelProviderStub struct{ name, model string }

func (s catalogModelProviderStub) Name() string  { return s.name }
func (s catalogModelProviderStub) Model() string { return s.model }
func (s catalogModelProviderStub) Review(context.Context, application.ModelReviewRequest) (json.RawMessage, error) {
	return json.RawMessage(`{"disposition":"noise"}`), nil
}

func TestCatalogTriageModelSupportsCloudflareProvider(t *testing.T) {
	runtime := &catalogModelRuntimeStub{provider: catalogModelProviderStub{
		name: "cloudflare", model: "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
	}}
	call, name, err := newCatalogTriageModel(context.Background(), runtime, "cloudflare", "@cf/meta/llama-3.3-70b-instruct-fp8-fast")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.config.Provider != "cloudflare" || runtime.config.Model != "@cf/meta/llama-3.3-70b-instruct-fp8-fast" {
		t.Fatalf("config=%+v", runtime.config)
	}
	if call == nil || name != "cloudflare/@cf/meta/llama-3.3-70b-instruct-fp8-fast" {
		t.Fatalf("call=%v name=%q", call != nil, name)
	}
}

func TestCatalogTriageModelRequiresConfiguration(t *testing.T) {
	runtime := &catalogModelRuntimeStub{err: errors.New("ADVERSARY_MODEL is required")}
	_, _, err := newCatalogTriageModel(context.Background(), runtime, "", "")
	if err == nil || !strings.Contains(err.Error(), "--model-provider and --model") {
		t.Fatalf("missing model configuration error=%v", err)
	}
}
