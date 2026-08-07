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
