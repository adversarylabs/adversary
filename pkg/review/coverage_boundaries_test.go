package review

import (
	"encoding/json"
	"fmt"
	"io"
	"testing"
)

func BenchmarkDecodeValidateRenderLargeReview(b *testing.B) {
	data := largeReviewEnvelope(b, 2_000)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		envelope, err := DecodeRunEnvelope(data)
		if err != nil {
			b.Fatal(err)
		}
		if err := RenderTerminal(io.Discard, envelope.Result); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzDecodeRunEnvelope(f *testing.F) {
	valid := largeReviewEnvelope(f, 2)
	f.Add(valid)
	f.Add([]byte(`{"protocolVersion":2,"result":{}}`))
	f.Add([]byte(`{"protocolVersion":1,"result":{"adversary":{"name":"x"},"target":{},"positives":[],"observations":[],"findings":[],"suppressed":{"observations":0,"findings":1}}}`))
	f.Add([]byte{0xff, 0x00, '{', '}'})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			data = data[:64<<10]
		}
		envelope, err := DecodeRunEnvelope(data)
		if err != nil {
			return
		}
		if envelope.ProtocolVersion != ProtocolVersion {
			t.Fatalf("accepted protocol version %d", envelope.ProtocolVersion)
		}
		if err := RenderTerminal(io.Discard, envelope.Result); err != nil {
			t.Fatalf("validated envelope did not render: %v", err)
		}
		encoded, err := json.Marshal(envelope)
		if err != nil {
			t.Fatalf("validated envelope did not encode: %v", err)
		}
		if _, err := DecodeRunEnvelope(encoded); err != nil {
			t.Fatalf("validated envelope did not round-trip: %v", err)
		}
	})
}

type benchmarkFataler interface {
	Helper()
	Fatal(...any)
}

func largeReviewEnvelope(tb benchmarkFataler, findings int) []byte {
	tb.Helper()
	type envelope struct {
		ProtocolVersion int          `json:"protocolVersion"`
		Result          ReviewResult `json:"result"`
	}
	result := ReviewResult{
		Adversary:    ReviewAdversary{Name: "benchmark/reviewer", Version: "1.0.0"},
		Target:       ReviewTarget{Repository: "/workspace/repository"},
		Positives:    []Note{},
		Observations: []Note{},
		Findings:     make([]Finding, findings),
		Suppressed:   Suppressed{},
	}
	for i := range result.Findings {
		line := i + 1
		result.Findings[i] = Finding{
			ID: fmt.Sprintf("finding-%05d", i), Title: "Deterministic benchmark finding", Category: "quality",
			Severity: "medium", Confidence: "high", Summary: "A bounded review finding used to exercise protocol decoding and rendering.",
			Evidence: []Evidence{{File: fmt.Sprintf("src/file-%05d.go", i), Line: &line, Message: "benchmark evidence"}},
		}
	}
	data, err := json.Marshal(envelope{ProtocolVersion: ProtocolVersion, Result: result})
	if err != nil {
		tb.Fatal(err)
	}
	return data
}
