package normalize

import (
	"strings"
	"testing"
)

func TestFromAdversaryJSON(t *testing.T) {
	raw := []byte(`{
	  "protocolVersion": 1,
	  "result": {
	    "adversary": {"name": "engineering-review", "version": "0.0.11"},
	    "findings": [{
	      "id": "er-1",
	      "title": "Leak",
	      "category": "reliability",
	      "severity": "high",
	      "summary": "Engineering Review: worker may leak after shutdown",
	      "recommendation": "cancel context",
	      "evidence": [{"file": "a.go", "line": 10, "message": "go worker()"}]
	    }]
	  }
	}`)
	r, err := FromAdversaryJSON("engineering-review", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings=%d", len(r.Findings))
	}
	if strings.Contains(r.Findings[0].Claim, "Engineering Review:") {
		t.Fatalf("tool identity not stripped: %q", r.Findings[0].Claim)
	}
	if r.Findings[0].File != "a.go" || r.Findings[0].Severity != "high" {
		t.Fatalf("%+v", r.Findings[0])
	}
}

func TestFromMultiRunJSONMergesComposition(t *testing.T) {
	raw := []byte(`{
	  "schemaVersion": 1,
	  "command": "run",
	  "data": {
	    "results": [
	      {
	        "adversary": "local/torvalds",
	        "output": {
	          "protocolVersion": 1,
	          "result": {
	            "adversary": {"name": "local/torvalds"},
	            "findings": [{
	              "id": "ship-1",
	              "title": "OK",
	              "category": "opinion",
	              "severity": "info",
	              "summary": "Looks fine",
	              "evidence": [{"file": "a.go", "line": 1}]
	            }]
	          }
	        }
	      },
	      {
	        "adversary": "go/security",
	        "output": {
	          "protocolVersion": 1,
	          "result": {
	            "adversary": {"name": "go/security"},
	            "findings": [{
	              "id": "tls-1",
	              "title": "TLS skip",
	              "category": "security",
	              "severity": "high",
	              "summary": "InsecureSkipVerify",
	              "evidence": [{"file": "b.go", "line": 2, "message": "skip verify"}]
	            }]
	          }
	        }
	      }
	    ]
	  }
	}`)
	r, err := FromAnyJSON("torvalds", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("want 2 merged findings, got %d: %+v", len(r.Findings), r.Findings)
	}
	if r.ReviewerID != "torvalds" {
		t.Fatalf("reviewer %q", r.ReviewerID)
	}
}

func TestFromAnyJSONRejectsIncompleteComposition(t *testing.T) {
	valid := `{"protocolVersion":1,"result":{"adversary":{"name":"ok"},"findings":[]}}`
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "one member fails after another succeeds",
			raw:  `{"command":"run","data":{"results":[{"adversary":"ok","output":` + valid + `},{"adversary":"broken","error":"child crashed"}]}}`,
		},
		{
			name: "all members fail",
			raw:  `{"command":"run","data":{"results":[{"adversary":"a","error":"boom"},{"adversary":"b","error":"bang"}]}}`,
		},
		{
			name: "member output is missing",
			raw:  `{"command":"run","data":{"results":[{"adversary":"empty"}]}}`,
		},
		{
			name: "member output is null",
			raw:  `{"command":"run","data":{"results":[{"adversary":"empty","output":null}]}}`,
		},
		{
			name: "member output has unrelated json",
			raw:  `{"command":"run","data":{"results":[{"adversary":"bad","output":{"unexpected":true}}]}}`,
		},
		{
			name: "member protocol result is null",
			raw:  `{"command":"run","data":{"results":[{"adversary":"bad","output":{"protocolVersion":1,"result":null}}]}}`,
		},
		{
			name: "composition contains no members",
			raw:  `{"command":"run","data":{"results":[]}}`,
		},
		{
			name: "run envelope omits results",
			raw:  `{"command":"run","data":{}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := FromAnyJSON("local-product", []byte(tc.raw))
			if err == nil {
				t.Fatalf("incomplete composition normalized as success: %+v", r)
			}
			if !strings.Contains(err.Error(), "composition") {
				t.Fatalf("error does not identify composition failure: %v", err)
			}
		})
	}
}

func TestFromMultiRunJSONAcceptsBareResultsEnvelope(t *testing.T) {
	raw := []byte(`{
	  "results": [{
	    "adversary": "local/product",
	    "output": {"protocolVersion":1,"result":{"adversary":{"name":"local/product"},"findings":[]}}
	  }]
	}`)
	r, err := FromAnyJSON("local-product", raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.ReviewerID != "local-product" || len(r.Findings) != 0 {
		t.Fatalf("unexpected normalized review: %+v", r)
	}
}

func TestFromBaselineJSON(t *testing.T) {
	raw := []byte(`{
	  "summary": "baseline",
	  "findings": [{
	    "id": "b1",
	    "file": "b.go",
	    "line": 3,
	    "severity": "medium",
	    "category": "correctness",
	    "claim": "check errors",
	    "evidence": "return ignored"
	  }]
	}`)
	r, err := FromBaselineJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.ReviewerID != "generic-baseline" || len(r.Findings) != 1 {
		t.Fatalf("%+v", r)
	}
}
