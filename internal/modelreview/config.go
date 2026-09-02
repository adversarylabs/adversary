package modelreview

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const (
	ProviderEnv                   = "ADVERSARY_MODEL_PROVIDER"
	ModelEnv                      = "ADVERSARY_MODEL"
	OpenAIKeyEnv                  = "OPENAI_API_KEY"
	OpenAIBaseURLEnv              = "ADVERSARY_OPENAI_BASE_URL"
	AnthropicKeyEnv               = "ANTHROPIC_API_KEY"
	AnthropicBaseURLEnv           = "ADVERSARY_ANTHROPIC_BASE_URL"
	FireworksKeyEnv               = "FIREWORKS_API_KEY"
	FireworksBaseURLEnv           = "ADVERSARY_FIREWORKS_BASE_URL"
	FireworksReasoningEffortEnv   = "ADVERSARY_FIREWORKS_REASONING_EFFORT"
	FireworksResponseFormatEnv    = "ADVERSARY_FIREWORKS_RESPONSE_FORMAT"
	FireworksStructuredRetriesEnv = "ADVERSARY_FIREWORKS_STRUCTURED_RETRIES"
	CamelKeyEnv                   = "CAMEL_API_KEY"
	CamelBaseURLEnv               = "ADVERSARY_CAMEL_BASE_URL"
	CamelReasoningEffortEnv       = "ADVERSARY_CAMEL_REASONING_EFFORT"
	CamelResponseFormatEnv        = "ADVERSARY_CAMEL_RESPONSE_FORMAT"
	CamelStructuredRetriesEnv     = "ADVERSARY_CAMEL_STRUCTURED_RETRIES"
	ModelContentDiagnosticsEnv    = "ADVERSARY_MODEL_CONTENT_DIAGNOSTICS"
	DisableKeepAlivesEnv          = "ADVERSARY_MODEL_DISABLE_KEEP_ALIVES"
)

type LookupEnv func(string) (string, bool)

type Config struct {
	Provider string
	Model    string
}

// HTTPClientFromEnvironment returns a provider client with the standard Go
// transport settings. Long-running requests to local or overlay-network model
// servers can opt out of pooled connections so every review round starts on a
// fresh socket rather than reusing one the remote server has silently dropped.
func HTTPClientFromEnvironment(lookup LookupEnv) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = envEnabled(lookup, DisableKeepAlivesEnv)
	return &http.Client{Transport: transport}
}

func ProviderFromEnvironment(lookup LookupEnv, client *http.Client) (Provider, error) {
	return ProviderFromConfig(Config{}, lookup, client)
}

func ProviderFromConfig(config Config, lookup LookupEnv, client *http.Client) (Provider, error) {
	if lookup == nil {
		return nil, fmt.Errorf("model environment lookup is required")
	}
	provider := strings.TrimSpace(config.Provider)
	if provider == "" {
		provider = normalizedEnv(lookup, ProviderEnv)
	}
	openAIKey := normalizedEnv(lookup, OpenAIKeyEnv)
	anthropicKey := normalizedEnv(lookup, AnthropicKeyEnv)
	fireworksKey := normalizedEnv(lookup, FireworksKeyEnv)
	camelKey := normalizedEnv(lookup, CamelKeyEnv)
	if provider == "" {
		configured := configuredProviders(openAIKey, anthropicKey, fireworksKey, camelKey)
		switch len(configured) {
		case 0:
			return nil, fmt.Errorf("model access requires %s, %s, %s, or %s", OpenAIKeyEnv, AnthropicKeyEnv, FireworksKeyEnv, CamelKeyEnv)
		case 1:
			provider = configured[0]
		default:
			return nil, fmt.Errorf("%s is required when multiple model provider keys are configured", ProviderEnv)
		}
	}
	model := strings.TrimSpace(config.Model)
	if model == "" {
		model = normalizedEnv(lookup, ModelEnv)
	}
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
	case "fireworks":
		if fireworksKey == "" {
			return nil, fmt.Errorf("%s is required for model provider fireworks", FireworksKeyEnv)
		}
		reasoningEffort, err := fireworksReasoningEffortFromEnvironment(lookup)
		if err != nil {
			return nil, err
		}
		structuredRetries, err := boundedIntegerFromEnvironment(lookup, FireworksStructuredRetriesEnv, 0, 3)
		if err != nil {
			return nil, err
		}
		responseFormat, err := fireworksResponseFormatFromEnvironment(lookup)
		if err != nil {
			return nil, err
		}
		return &FireworksProvider{
			APIKey:                    fireworksKey,
			ModelID:                   model,
			BaseURL:                   valueOrDefault(normalizedEnv(lookup, FireworksBaseURLEnv), "https://api.fireworks.ai/inference"),
			Client:                    client,
			ReasoningEffort:           reasoningEffort,
			ResponseFormat:            responseFormat,
			StructuredOutputRetries:   structuredRetries,
			IncludeContentDiagnostics: envEnabled(lookup, ModelContentDiagnosticsEnv),
		}, nil
	case "camel", "camel-stream":
		if camelKey == "" {
			return nil, fmt.Errorf("%s is required for model provider camel", CamelKeyEnv)
		}
		reasoningEffort, err := reasoningEffortFromEnvironment(lookup, CamelReasoningEffortEnv)
		if err != nil {
			return nil, err
		}
		structuredRetries, err := boundedIntegerFromEnvironment(lookup, CamelStructuredRetriesEnv, 0, 3)
		if err != nil {
			return nil, err
		}
		responseFormat, err := responseFormatFromEnvironment(lookup, CamelResponseFormatEnv, "json_object")
		if err != nil {
			return nil, err
		}
		return &CamelProvider{
			APIKey:                    camelKey,
			ModelID:                   model,
			BaseURL:                   valueOrDefault(normalizedEnv(lookup, CamelBaseURLEnv), "https://stream.camelai.com"),
			Client:                    client,
			ReasoningEffort:           reasoningEffort,
			ResponseFormat:            responseFormat,
			StructuredOutputRetries:   structuredRetries,
			IncludeContentDiagnostics: envEnabled(lookup, ModelContentDiagnosticsEnv),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported %s %q (supported: openai, anthropic, fireworks, camel)", ProviderEnv, provider)
	}
}

func fireworksResponseFormatFromEnvironment(lookup LookupEnv) (string, error) {
	return responseFormatFromEnvironment(lookup, FireworksResponseFormatEnv, "json_schema")
}

func responseFormatFromEnvironment(lookup LookupEnv, name, defaultFormat string) (string, error) {
	format := strings.ToLower(normalizedEnv(lookup, name))
	switch format {
	case "":
		return defaultFormat, nil
	case "json_schema", "json_object":
		return format, nil
	default:
		return "", fmt.Errorf("unsupported %s %q (supported: json_schema, json_object)", name, format)
	}
}

func boundedIntegerFromEnvironment(lookup LookupEnv, name string, minimum, maximum int) (int, error) {
	value := normalizedEnv(lookup, name)
	if value == "" {
		return minimum, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s must be an integer from %d through %d", name, minimum, maximum)
	}
	return parsed, nil
}

func fireworksReasoningEffortFromEnvironment(lookup LookupEnv) (string, error) {
	return reasoningEffortFromEnvironment(lookup, FireworksReasoningEffortEnv)
}

func reasoningEffortFromEnvironment(lookup LookupEnv, name string) (string, error) {
	effort := strings.ToLower(normalizedEnv(lookup, name))
	switch effort {
	case "", "none", "low", "medium", "high":
		return effort, nil
	default:
		return "", fmt.Errorf("unsupported %s %q (supported: none, low, medium, high)", name, effort)
	}
}

func configuredProviders(openAIKey, anthropicKey, fireworksKey, camelKey string) []string {
	var configured []string
	for _, candidate := range []struct {
		name string
		key  string
	}{
		{name: "openai", key: openAIKey},
		{name: "anthropic", key: anthropicKey},
		{name: "fireworks", key: fireworksKey},
		{name: "camel", key: camelKey},
	} {
		if candidate.key != "" {
			configured = append(configured, candidate.name)
		}
	}
	return configured
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

func envEnabled(lookup LookupEnv, name string) bool {
	if lookup == nil {
		return false
	}
	value := normalizedEnv(lookup, name)
	return strings.EqualFold(value, "true") || value == "1" || strings.EqualFold(value, "yes")
}
