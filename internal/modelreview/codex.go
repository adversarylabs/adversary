package modelreview

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CodexProvider uses the user's installed Codex and ChatGPT login. It never
// falls back to an API provider or modifies the user's authentication.
type CodexProvider struct {
	ModelID         string
	ReasoningEffort string
	binary          string // test seam; production always resolves codex on PATH
}

func (*CodexProvider) Name() string    { return "codex" }
func (p *CodexProvider) Model() string { return p.ModelID }

func codexError(message string) error {
	return &ProviderError{Code: "codex_provider_failure", Message: message, Retryable: false}
}

func (p *CodexProvider) Review(ctx context.Context, request Request) (Result, error) {
	if request.Budget.TimeoutMS > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(request.Budget.TimeoutMS)*time.Millisecond)
		defer cancel()
	}
	binary := p.binary
	if binary == "" {
		var err error
		binary, err = exec.LookPath("codex")
		if err != nil {
			return Result{}, codexError("install Codex CLI and run codex login before using provider codex")
		}
	}
	home := os.Getenv("CODEX_HOME")
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return Result{}, codexError("cannot locate Codex home")
		}
		home = filepath.Join(userHome, ".codex")
	}
	home, err := filepath.Abs(home)
	if err != nil {
		return Result{}, err
	}
	// Lock the same home across all adversary processes; waiting consumes the
	// request deadline. Codex itself remains responsible for refreshing auth.
	lock, err := os.OpenFile(filepath.Join(home, ".adversary-review.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return Result{}, codexError("cannot lock Codex home; run codex login first and ensure CODEX_HOME is writable")
	}
	defer lock.Close()
	for {
		acquired, err := tryCodexLock(lock)
		if err != nil {
			return Result{}, codexError("cannot lock Codex authentication")
		}
		if acquired {
			break
		}
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	defer unlockCodex(lock)
	dir, err := os.MkdirTemp("", "adversary-codex-")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(dir)
	env := codexEnvironment(os.Environ(), home)
	command := func(args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Dir, cmd.Env = dir, env
		cmd.WaitDelay = time.Second
		configureCodexProcess(cmd)
		return cmd
	}
	var status cappedCodexBuffer
	login := command("login", "status")
	login.Stdout, login.Stderr = &status, &status
	if err := login.Run(); err != nil || !strings.Contains(status.String(), "Logged in using ChatGPT") {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return Result{}, codexError("Codex requires a ChatGPT subscription login; run codex login interactively (API-key login is not accepted)")
	}
	schemaPath, outputPath := filepath.Join(dir, "schema.json"), filepath.Join(dir, "output.json")
	if err := os.WriteFile(schemaPath, []byte(codexOutputSchema), 0600); err != nil {
		return Result{}, err
	}
	effort := p.ReasoningEffort
	if effort == "" {
		effort = "high"
	}
	cmd := command("exec", "--ignore-user-config", "--ephemeral", "--skip-git-repo-check",
		"--sandbox", "read-only", "--json", "--model", p.ModelID,
		"--output-schema", schemaPath, "--output-last-message", outputPath,
		"-c", "model_provider=\"openai\"", "-c", "model_reasoning_effort="+strconv.Quote(effort),
		"-c", "features.shell_tool=false", "-c", "features.unified_exec=false",
		"-c", "features.multi_agent=false", "-c", "apps._default.enabled=false",
		"-c", "web_search=\"disabled\"", "-c", "tools.view_image=false", "-")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("Use only the supplied input; do not use tools. Follow the review instructions below. Your result must match the result schema. Encode that entire result as a JSON string in the response envelope field result_json. Target at most %d output tokens.\n\nReview instructions:\n%s\n\nResult schema:\n%s\n\nInput JSON:\n%s", request.Budget.MaximumOutputTokens, request.Prompt, request.Schema, request.Input))
	var events cappedCodexBuffer
	cmd.Stdout = &events
	// Diagnostics can contain input or credentials. Do not expose or retain them.
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return Result{}, codexError("Codex execution failed; check codex login status, subscription limits, model access, and that Codex supports --ignore-user-config (no API fallback attempted)")
	}
	file, err := os.Open(outputPath)
	if err != nil {
		return Result{}, codexError("Codex did not produce a final JSON response")
	}
	defer file.Close()
	output, err := io.ReadAll(io.LimitReader(file, MaxProviderBytes+1))
	if err != nil || len(output) > MaxProviderBytes {
		return Result{}, codexError("Codex response exceeds output limit or could not be read")
	}
	var envelope struct {
		ResultJSON string `json:"result_json"`
	}
	if err := ValidateOutput(json.RawMessage(codexOutputSchema), output); err != nil {
		return Result{}, codexError("Codex response does not match the response envelope schema")
	}
	if err := json.Unmarshal(output, &envelope); err != nil {
		return Result{}, codexError("Codex response could not be decoded")
	}
	output = []byte(envelope.ResultJSON)
	if err := ValidateOutput(request.Schema, output); err != nil {
		return Result{}, codexError("Codex response does not match the requested JSON schema")
	}
	result := Result{Output: output}
	for _, line := range bytes.Split(events.Bytes(), []byte{'\n'}) {
		var event struct {
			Type  string `json:"type"`
			Usage struct {
				Input  int `json:"input_tokens"`
				Output int `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(line, &event) == nil && event.Type == "turn.completed" {
			result.Usage.InputTokens += event.Usage.Input
			result.Usage.OutputTokens += event.Usage.Output
		}
	}
	return result, nil
}

func codexEnvironment(environment []string, home string) []string {
	var result []string
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if upper == "CODEX_HOME" || strings.Contains(upper, "API_KEY") || strings.Contains(upper, "ACCESS_TOKEN") || strings.HasPrefix(upper, "OPENAI_") || strings.HasSuffix(upper, "_KEY") || strings.HasSuffix(upper, "_TOKEN") || strings.HasSuffix(upper, "_SECRET") || strings.HasSuffix(upper, "_PASSWORD") {
			continue
		}
		result = append(result, entry)
	}
	return append(result, "CODEX_HOME="+home)
}

// A string envelope supports arbitrary adversary schemas (including optional
// fields) without rewriting them into OpenAI's stricter JSON Schema dialect.
// The decoded result is still validated against the original schema.
const codexOutputSchema = `{"type":"object","properties":{"result_json":{"type":"string"}},"required":["result_json"],"additionalProperties":false}`

type cappedCodexBuffer struct{ bytes.Buffer }

func (b *cappedCodexBuffer) Write(data []byte) (int, error) {
	n := len(data)
	if remaining := MaxProviderBytes - b.Len(); remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = b.Buffer.Write(data)
	}
	return n, nil
}
