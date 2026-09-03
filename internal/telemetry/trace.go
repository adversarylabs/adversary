package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/pkg/adversarylabs"
)

const (
	MaxTags        = 32
	MaxTagKeyLen   = 64
	MaxTagValueLen = 128
)

var tagKeyRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]*$`)

// ParseTags validates repeatable key=value CLI tags. Tags are uploaded and
// therefore intentionally constrained to short, low-cardinality labels.
func ParseTags(values []string) (map[string]string, error) {
	if len(values) > MaxTags {
		return nil, fmt.Errorf("at most %d --tag values are allowed", MaxTags)
	}
	tags := make(map[string]string, len(values))
	for _, raw := range values {
		key, value, ok := strings.Cut(raw, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || key == "" || value == "" {
			return nil, fmt.Errorf("tag %q must be key=value", raw)
		}
		if len(key) > MaxTagKeyLen || !tagKeyRE.MatchString(key) {
			return nil, fmt.Errorf("tag key %q must start with a letter and contain at most %d letters, numbers, dots, dashes, or underscores", key, MaxTagKeyLen)
		}
		if len(value) > MaxTagValueLen {
			return nil, fmt.Errorf("tag %q value exceeds %d characters", key, MaxTagValueLen)
		}
		if _, exists := tags[key]; exists {
			return nil, fmt.Errorf("tag %q was provided more than once", key)
		}
		tags[key] = value
	}
	return tags, nil
}

// BuildTrace creates a trace with one root run span and one child span per
// adversary invocation. Times are carried as decimal strings, matching OTLP
// JSON and avoiding loss of nanosecond precision in JavaScript consumers.
func BuildTrace(report adversarylabs.RunUsageReport, started, ended time.Time) adversarylabs.RunUsageReport {
	if ended.Before(started) {
		ended = started
	}
	report.TraceID = randomHex(16)
	rootID := randomHex(8)
	report.Spans = append(report.Spans, adversarylabs.RunUsageSpan{
		TraceID: report.TraceID, SpanID: rootID, Name: "adversary run", Kind: 1,
		StartTimeUnixNano: unixNanoString(started), EndTimeUnixNano: unixNanoString(ended), Status: runStatus(report.Results),
		Attributes: map[string]any{
			"adversary.run.adversary_count": len(report.Adversaries),
			"adversary.run.duration_ms":     report.DurationMS,
		},
	})
	for i := range report.Results {
		result := &report.Results[i]
		childStart, childEnd := parseResultTimes(*result, started, ended)
		result.StartedAtUnixNano = unixNanoString(childStart)
		result.EndedAtUnixNano = unixNanoString(childEnd)
		attrs := map[string]any{
			"adversary.id":                    result.Adversary,
			"adversary.run.duration_ms":       result.DurationMS,
			"adversary.run.findings.critical": result.CriticalCount,
			"adversary.run.findings.high":     result.HighCount,
			"adversary.run.findings.medium":   result.MediumCount,
			"adversary.run.findings.low":      result.LowCount,
			"adversary.run.findings.info":     result.InfoCount,
		}
		if result.Scope != "" {
			attrs["adversary.run.scope"] = result.Scope
		}
		report.Spans = append(report.Spans, adversarylabs.RunUsageSpan{
			TraceID: report.TraceID, SpanID: randomHex(8), ParentSpanID: rootID,
			Name: "adversary review", Kind: 1, StartTimeUnixNano: unixNanoString(childStart),
			EndTimeUnixNano: unixNanoString(childEnd), Status: result.Status, Attributes: attrs,
		})
	}
	return report
}

func parseResultTimes(result adversarylabs.RunUsageAdversaryResult, fallbackStart, fallbackEnd time.Time) (time.Time, time.Time) {
	start, end := fallbackStart, fallbackEnd
	if n, err := strconv.ParseInt(result.StartedAtUnixNano, 10, 64); err == nil && n > 0 {
		start = time.Unix(0, n)
	}
	if n, err := strconv.ParseInt(result.EndedAtUnixNano, 10, 64); err == nil && n > 0 {
		end = time.Unix(0, n)
	}
	if end.Before(start) {
		end = start
	}
	return start, end
}

func runStatus(results []adversarylabs.RunUsageAdversaryResult) string {
	status := "completed"
	for _, result := range results {
		if result.Status == "failed" {
			return "error"
		}
		if result.Status == "partial" {
			status = "error"
		}
	}
	return status
}

func randomHex(bytes int) string {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("0", bytes*2)
	}
	return hex.EncodeToString(b)
}

func unixNanoString(t time.Time) string { return strconv.FormatInt(t.UnixNano(), 10) }

type otlpAttribute struct {
	Key   string    `json:"key"`
	Value otlpValue `json:"value"`
}
type otlpValue struct {
	StringValue string `json:"stringValue,omitempty"`
	IntValue    string `json:"intValue,omitempty"`
	BoolValue   *bool  `json:"boolValue,omitempty"`
}

// OTLPJSON returns a valid OTLP/HTTP JSON traces request.
func OTLPJSON(report adversarylabs.RunUsageReport, cliVersion string) ([]byte, error) {
	spans := make([]map[string]any, 0, len(report.Spans))
	for _, span := range report.Spans {
		attrs := make([]otlpAttribute, 0, len(span.Attributes)+len(report.Tags))
		for key, value := range span.Attributes {
			attrs = append(attrs, makeOTLPAttribute(key, value))
		}
		if span.ParentSpanID == "" {
			for key, value := range report.Tags {
				attrs = append(attrs, makeOTLPAttribute("adversary.run.tag."+key, value))
			}
		}
		statusCode := 1
		if span.Status == "failed" || span.Status == "error" {
			statusCode = 2
		}
		spans = append(spans, map[string]any{
			"traceId": span.TraceID, "spanId": span.SpanID, "parentSpanId": span.ParentSpanID,
			"name": span.Name, "kind": span.Kind, "startTimeUnixNano": span.StartTimeUnixNano,
			"endTimeUnixNano": span.EndTimeUnixNano, "attributes": attrs,
			"status": map[string]any{"code": statusCode},
		})
	}
	payload := map[string]any{"resourceSpans": []any{map[string]any{
		"resource": map[string]any{"attributes": []otlpAttribute{
			makeOTLPAttribute("service.name", "adversary-cli"),
			makeOTLPAttribute("service.version", cliVersion),
			makeOTLPAttribute("telemetry.sdk.language", "go"),
		}},
		"scopeSpans": []any{map[string]any{"scope": map[string]any{"name": "github.com/adversarylabs/adversary"}, "spans": spans}},
	}}}
	return json.Marshal(payload)
}

func makeOTLPAttribute(key string, value any) otlpAttribute {
	attribute := otlpAttribute{Key: key}
	switch v := value.(type) {
	case bool:
		attribute.Value.BoolValue = &v
	case int:
		attribute.Value.IntValue = strconv.Itoa(v)
	case int64:
		attribute.Value.IntValue = strconv.FormatInt(v, 10)
	case float64:
		attribute.Value.IntValue = strconv.FormatInt(int64(v), 10)
	default:
		attribute.Value.StringValue = fmt.Sprint(v)
	}
	return attribute
}

// AppendOTLPFile appends one OTLP traces request per line so interrupted and
// concurrent benchmark processes retain already-completed runs.
func AppendOTLPFile(path string, payload []byte) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	if _, err := w.Write(append(payload, '\n')); err != nil {
		return err
	}
	return w.Flush()
}

// ExportOTLPHTTP sends an OTLP JSON request when a standard OTLP endpoint is
// configured. An endpoint ending before /v1/traces receives that suffix.
func ExportOTLPHTTP(ctx context.Context, payload []byte) error {
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"))
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	}
	if endpoint == "" {
		return nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("parse OTLP endpoint: %w", err)
	}
	if !strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/v1/traces") {
		u.Path = strings.TrimRight(u.Path, "/") + "/v1/traces"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for _, pair := range strings.Split(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"), ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if ok && key != "" {
			req.Header.Set(key, value)
		}
	}
	timeout := 10 * time.Second
	if raw := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT")); raw == "" {
		raw = strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TIMEOUT"))
		if raw != "" {
			if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
				timeout = time.Duration(ms) * time.Millisecond
			}
		}
	} else if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
		timeout = time.Duration(ms) * time.Millisecond
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("OTLP exporter returned %s", resp.Status)
	}
	return nil
}
