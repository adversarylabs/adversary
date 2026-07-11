package review

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var errorCodeRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

type ErrorEnvelope struct {
	ProtocolVersion int           `json:"protocolVersion"`
	Error           ProtocolError `json:"error"`
}

type ProtocolError struct {
	Code      string                     `json:"code"`
	Message   string                     `json:"message"`
	Retryable bool                       `json:"retryable"`
	Details   map[string]json.RawMessage `json:"details"`
}

func DecodeErrorEnvelope(data []byte) (ErrorEnvelope, error) {
	var out ErrorEnvelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, err
	}
	if err := ensureJSONEOF(dec); err != nil {
		return out, err
	}
	if out.ProtocolVersion != ProtocolVersion {
		return out, fmt.Errorf("unsupported adversary error protocolVersion %d", out.ProtocolVersion)
	}
	if !errorCodeRE.MatchString(out.Error.Code) {
		return out, fmt.Errorf("invalid adversary error code %q", out.Error.Code)
	}
	if strings.TrimSpace(out.Error.Message) == "" {
		return out, fmt.Errorf("invalid adversary error message")
	}
	if out.Error.Details == nil {
		return out, fmt.Errorf("invalid adversary error details: object is required")
	}
	return out, nil
}

func EncodeErrorEnvelope(value ProtocolError) ([]byte, error) {
	initial, err := json.Marshal(ErrorEnvelope{ProtocolVersion: ProtocolVersion, Error: value})
	if err != nil {
		return nil, err
	}
	if _, err := DecodeErrorEnvelope(initial); err != nil {
		return nil, err
	}
	var canonical any
	if err := json.Unmarshal(initial, &canonical); err != nil {
		return nil, err
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
