package adversarylabs

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var requestIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var validationFieldPattern = regexp.MustCompile(`^(body|repository|repository_id|pull_request|review_node_id|head_sha|comments(\[[0-9]{1,2}\](\.(adversary|package_name|package_version|finding_id|rule_id|path|body))?)?)$`)

// responseError accepts only bounded, known diagnostics. An upstream proxy or
// server can echo credentials and request bodies even in JSON error messages,
// so arbitrary messages, headers, and raw response bodies must never be logged.
func responseError(resp *http.Response, token string) error {
	message := fmt.Sprintf("request failed: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	var body struct {
		Error     string `json:"error"`
		Code      string `json:"code"`
		Field     string `json:"field"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}
	const maxErrorBytes = 8 * 1024
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes+1))
	if err == nil && len(data) <= maxErrorBytes && json.Unmarshal(data, &body) == nil {
		switch body.Error {
		case "invalid_request", "invalid_json", "unauthorized", "insufficient_scope", "repository_mismatch":
			message += ": " + body.Error
		}
		if body.Error == "invalid_request" {
			reason := ""
			switch body.Code {
			case "required":
				reason = "required field is missing or empty"
			case "invalid_type":
				reason = "field has an invalid type"
			case "invalid_format":
				reason = "field has an invalid format"
			case "out_of_range":
				reason = "field is outside the allowed range"
			case "too_long":
				reason = "field exceeds the length limit"
			case "too_many_items":
				reason = "array exceeds the item limit"
			case "duplicate_finding":
				reason = "finding_id must be unique per adversary and package in a review"
			}
			// Older servers return only a message for the original collision.
			if reason == "" && body.Message == "finding_id must be unique per review" {
				reason = body.Message
			}
			if reason != "" {
				message += ": " + reason
				if validationFieldPattern.MatchString(body.Field) {
					message += " (" + body.Field + ")"
				}
			}
		}
	}
	requestID := resp.Header.Get("X-Request-ID")
	if !requestIDPattern.MatchString(requestID) {
		requestID = body.RequestID
	}
	if requestIDPattern.MatchString(requestID) {
		message += " [request_id=" + requestID + "]"
	}
	if token != "" {
		message = strings.ReplaceAll(message, token, "[redacted]")
	}
	return fmt.Errorf("%s", message)
}
