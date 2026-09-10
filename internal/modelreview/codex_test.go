package modelreview

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func init() {
	if os.Getenv("ADVERSARY_TEST_CODEX_HELPER") != "1" {
		return
	}
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "login" {
		if os.Getenv("ADVERSARY_TEST_CODEX_MODE") == "api" {
			fmt.Println("Logged in using an API key")
		} else {
			fmt.Println("Logged in using ChatGPT")
		}
		os.Exit(0)
	}
	for _, expected := range []string{"--ignore-user-config", "--ephemeral", "--sandbox", "read-only", "--output-schema", "features.shell_tool=false", "features.unified_exec=false", "web_search=\"disabled\""} {
		found := false
		for _, arg := range args {
			if arg == expected {
				found = true
			}
		}
		if !found {
			os.Exit(8)
		}
	}
	if os.Getenv("OPENAI_API_KEY") != "" {
		os.Exit(9)
	}
	if os.Getenv("ADVERSARY_TEST_CODEX_MODE") == "slow" {
		time.Sleep(time.Minute)
	}
	prompt, err := io.ReadAll(os.Stdin)
	if err != nil || !strings.Contains(string(prompt), "Input JSON:") || !strings.Contains(string(prompt), "Result schema:") {
		os.Exit(6)
	}
	output := `{"ok":true}`
	if os.Getenv("ADVERSARY_TEST_CODEX_MODE") == "invalid" {
		output = `{"ok":"wrong"}`
	}
	wrapped, _ := json.Marshal(map[string]string{"result_json": output})
	if os.Getenv("ADVERSARY_TEST_CODEX_MODE") == "bad-envelope" {
		wrapped = []byte(`{"unexpected":true}`)
	}
	if os.Getenv("ADVERSARY_TEST_CODEX_MODE") == "failed" {
		os.Exit(1)
	}
	for i, arg := range args {
		if arg == "--output-schema" {
			schema, err := os.ReadFile(args[i+1])
			if err != nil || string(schema) != codexOutputSchema {
				os.Exit(7)
			}
		}
		if arg == "--output-last-message" {
			_ = os.WriteFile(args[i+1], wrapped, 0600)
		}
	}
	fmt.Println(`{"type":"turn.completed","usage":{"input_tokens":123,"output_tokens":45}}`)
	os.Exit(0)
}

func codexTestProvider(t *testing.T) *CodexProvider {
	t.Helper()
	t.Setenv("CODEX_HOME", t.TempDir())
	t.Setenv("ADVERSARY_TEST_CODEX_HELPER", "1")
	t.Setenv("OPENAI_API_KEY", "must-not-reach-child")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return &CodexProvider{ModelID: "gpt-5.6-luna", binary: binary}
}
func codexTestRequest() Request {
	return Request{Prompt: "Review", Input: json.RawMessage(`{}`), Schema: json.RawMessage(`{"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"],"additionalProperties":false}`), Budget: Budget{MaximumOutputTokens: 100, TimeoutMS: 5000}}
}
func TestCodexReview(t *testing.T) {
	p := codexTestProvider(t)
	result, err := p.Review(context.Background(), codexTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Output) != `{"ok":true}` || result.Usage.InputTokens != 123 || result.Usage.OutputTokens != 45 {
		t.Fatalf("unexpected result: %+v", result)
	}
}
func TestCodexRejectsAPIAuthAndInvalidOutput(t *testing.T) {
	for _, mode := range []string{"api", "invalid", "bad-envelope", "failed"} {
		t.Run(mode, func(t *testing.T) {
			p := codexTestProvider(t)
			t.Setenv("ADVERSARY_TEST_CODEX_MODE", mode)
			_, err := p.Review(context.Background(), codexTestRequest())
			var providerErr *ProviderError
			if !errors.As(err, &providerErr) || providerErr.Retryable {
				t.Fatalf("expected nonretryable error, got %v", err)
			}
		})
	}
}
func TestCodexCancellation(t *testing.T) {
	p := codexTestProvider(t)
	t.Setenv("ADVERSARY_TEST_CODEX_MODE", "slow")
	request := codexTestRequest()
	request.Budget.TimeoutMS = 150
	start := time.Now()
	_, err := p.Review(context.Background(), request)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Fatalf("cancellation: %v", err)
	}
}
func TestCodexLockWaitRespectsCancellation(t *testing.T) {
	p := codexTestProvider(t)
	file, err := os.OpenFile(os.Getenv("CODEX_HOME")+"/.adversary-review.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ok, err := tryCodexLock(file)
	if !ok || err != nil {
		t.Fatal(err)
	}
	defer unlockCodex(file)
	request := codexTestRequest()
	request.Budget.TimeoutMS = 100
	_, err = p.Review(context.Background(), request)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}
func TestCodexRouting(t *testing.T) {
	lookup := func(key string) (string, bool) {
		if key == OpenAIKeyEnv || key == CamelKeyEnv {
			return "configured", true
		}
		return "", false
	}
	for _, config := range []Config{{Model: "codex/gpt-5.6-luna"}, {Provider: "codex", Model: "gpt-5.6-luna"}} {
		p, err := ProviderFromConfig(config, lookup, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.Name() != "codex" || p.Model() != "gpt-5.6-luna" {
			t.Fatal(p)
		}
	}
	for _, config := range []Config{{Model: "codex/"}, {Provider: "openai", Model: "codex/gpt-5.6-luna"}} {
		if _, err := ProviderFromConfig(config, lookup, nil); err == nil {
			t.Fatalf("accepted %+v", config)
		}
	}
}
func TestCodexEnvironment(t *testing.T) {
	env := codexEnvironment([]string{"OPENAI_API_KEY=secret", "CODEX_API_KEY=secret", "RESEARCH_OPENAI_KEY=secret", "CODEX_HOME=old", "PATH=/bin"}, "/new")
	if strings.Contains(strings.Join(env, "\n"), "secret") {
		t.Fatal(env)
	}
}

func TestCodexAcceptsOptionalSchema(t *testing.T) {
	p := codexTestProvider(t)
	request := codexTestRequest()
	request.Schema = json.RawMessage(`{"type":"object","properties":{"ok":{"type":"boolean"},"optional":{"type":"string"}}}`)
	if _, err := p.Review(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}
