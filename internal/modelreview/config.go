package modelreview

import (
	"fmt"
	"net/http"
	"strings"
)

const (
	ProviderEnv         = "ADVERSARY_MODEL_PROVIDER"
	ModelEnv            = "ADVERSARY_MODEL"
	OpenAIKeyEnv        = "OPENAI_API_KEY"
	OpenAIBaseURLEnv    = "ADVERSARY_OPENAI_BASE_URL"
	AnthropicKeyEnv     = "ANTHROPIC_API_KEY"
	AnthropicBaseURLEnv = "ADVERSARY_ANTHROPIC_BASE_URL"
)

type LookupEnv func(string) (string, bool)

func ProviderFromEnvironment(lookup LookupEnv, client *http.Client) (Provider, error) {
	if lookup == nil {
		return nil, fmt.Errorf("model environment lookup is required")
	}
	provider := normalizedEnv(lookup, ProviderEnv)
	openAIKey := normalizedEnv(lookup, OpenAIKeyEnv)
	anthropicKey := normalizedEnv(lookup, AnthropicKeyEnv)
	if provider == "" {
		switch {
		case openAIKey != "" && anthropicKey == "":
			provider = "openai"
		case anthropicKey != "" && openAIKey == "":
			provider = "anthropic"
		case openAIKey == "" && anthropicKey == "":
			return nil, fmt.Errorf("model access requires %s or %s", OpenAIKeyEnv, AnthropicKeyEnv)
		default:
			return nil, fmt.Errorf("%s is required when multiple model provider keys are configured", ProviderEnv)
		}
	}
	model := normalizedEnv(lookup, ModelEnv)
	if model == "" {
		return nil, fmt.Errorf("%s is required for model-backed adversaries", ModelEnv)
	}
	switch strings.ToLower(provider) {
	case "openai":
		if openAIKey == "" {
			return nil, fmt.Errorf("%s is required for model provider openai", OpenAIKeyEnv)
		}
		return &OpenAIProvider{
			APIKey:  openAIKey,
			ModelID: model,
			BaseURL: valueOrDefault(normalizedEnv(lookup, OpenAIBaseURLEnv), "https://api.openai.com"),
			Client:  client,
		}, nil
	case "anthropic":
		if anthropicKey == "" {
			return nil, fmt.Errorf("%s is required for model provider anthropic", AnthropicKeyEnv)
		}
		return &AnthropicProvider{
			APIKey:  anthropicKey,
			ModelID: model,
			BaseURL: valueOrDefault(normalizedEnv(lookup, AnthropicBaseURLEnv), "https://api.anthropic.com"),
			Client:  client,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported %s %q (supported: openai, anthropic)", ProviderEnv, provider)
	}
}

func normalizedEnv(lookup LookupEnv, name string) string {
	value, _ := lookup(name)
	return strings.TrimSpace(value)
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return strings.TrimRight(value, "/")
}
