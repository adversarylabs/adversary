package outcomecontext

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestGitHubPullRequestBuildsBoundedAttributedSources(t *testing.T) {
	context := GitHubPullRequest("acme/app", 42, "  Add delegated trust  ", strings.Repeat("x", MaxSourceCharacters+10))
	if context == nil {
		t.Fatal("expected context")
	}
	if context.Subject.Repository != "acme/app" || context.Subject.PullRequest != 42 {
		t.Fatalf("subject = %#v", context.Subject)
	}
	if len(context.Sources) != 2 || context.Sources[0].Text != "Add delegated trust" {
		t.Fatalf("sources = %#v", context.Sources)
	}
	if context.Intent.Objective != "Add delegated trust" || context.Intent.Confidence != "low" {
		t.Fatalf("intent = %#v", context.Intent)
	}
	if err := context.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestGitHubPullRequestRejectsInvalidNumber(t *testing.T) {
	for _, number := range []int{0, -1} {
		if got := GitHubPullRequest("acme/app", number, "title", "body"); got != nil {
			t.Fatalf("number %d produced context %#v", number, got)
		}
	}
}

func TestGitHubPullRequestRejectsOverlongRepository(t *testing.T) {
	if got := GitHubPullRequest(strings.Repeat("r", MaxRepositoryCharacters+1), 1, "title", "body"); got != nil {
		t.Fatalf("overlong repository produced context %#v", got)
	}
}

func TestGitHubPullRequestRejectsEmptyRepository(t *testing.T) {
	for _, repository := range []string{"", " \t\n"} {
		if got := GitHubPullRequest(repository, 1, "title", "body"); got != nil {
			t.Fatalf("repository %q produced context %#v", repository, got)
		}
	}
}

func TestValidateMatchesSubjectAndUnicodeSchemaLimits(t *testing.T) {
	valid := GitHubPullRequest(strings.Repeat("r", MaxRepositoryCharacters), 1, strings.Repeat("🙂", MaxSourceCharacters), "body")
	if valid == nil || valid.Validate() != nil {
		t.Fatalf("boundary context = %#v", valid)
	}

	invalidRepository := *valid
	invalidRepository.Subject.Repository = strings.Repeat("r", MaxRepositoryCharacters+1)
	if err := invalidRepository.Validate(); err == nil {
		t.Fatal("expected repository length error")
	}
	invalidProvider := *valid
	invalidProvider.Subject.Provider = "gitlab"
	if err := invalidProvider.Validate(); err == nil {
		t.Fatal("expected provider error")
	}
	invalidSource := *valid
	invalidSource.Sources = []Source{{Kind: "pull_request_title", Text: strings.Repeat("🙂", MaxSourceCharacters+1)}}
	if err := invalidSource.Validate(); err == nil {
		t.Fatal("expected source character length error")
	}
}

func TestGitHubPullRequestOmitsEmptyContext(t *testing.T) {
	if got := GitHubPullRequest("acme/app", 42, " ", "\n"); got != nil {
		t.Fatalf("context = %#v", got)
	}
}

func TestValidateRejectsDuplicateSources(t *testing.T) {
	context := Context{
		SchemaVersion: SchemaVersion,
		Subject:       Subject{Provider: "github", Repository: "acme/app", PullRequest: 42},
		Sources: []Source{
			{Kind: "pull_request_title", Text: "one"},
			{Kind: "pull_request_title", Text: "two"},
		},
		Intent: Intent{Objective: "test", Confidence: "low"},
	}
	if err := context.Validate(); err == nil {
		t.Fatal("expected duplicate source validation error")
	}
}

func TestSchemaRejectsValuesRejectedByRuntimeValidation(t *testing.T) {
	schemaData, err := os.ReadFile(filepath.Join("..", "..", "schema", "adversary.outcome-context.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(schemaData, &document); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	const schemaURL = "https://adversary.dev/schemas/adversary.outcome-context.v1.schema.json"
	if err := compiler.AddResource(schemaURL, document); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatal(err)
	}

	valid := `{
		"schema_version":"adversary.outcome-context.v1",
		"subject":{"provider":"github","repository":"acme/app","pull_request":42},
		"sources":[{"kind":"pull_request_title","text":"Permit pulls"}],
		"intent":{"objective":"Permit pulls","confidence":"high","expected_effects":[],"must_preserve":[],"affected_boundaries":[],"ambiguities":[]}
	}`
	var value any
	if err := json.Unmarshal([]byte(valid), &value); err != nil {
		t.Fatal(err)
	}
	if err := compiled.Validate(value); err != nil {
		t.Fatalf("valid fixture rejected: %v", err)
	}

	invalid := map[string]string{
		"empty subject": `{
			"schema_version":"adversary.outcome-context.v1","subject":{},
			"sources":[{"kind":"pull_request_title","text":"Permit pulls"}],
			"intent":{"objective":"Permit pulls","confidence":"high","expected_effects":[],"must_preserve":[],"affected_boundaries":[],"ambiguities":[]}
		}`,
		"subject without pull request": `{
			"schema_version":"adversary.outcome-context.v1","subject":{"provider":"github","repository":"acme/app"},
			"sources":[{"kind":"pull_request_title","text":"Permit pulls"}],
			"intent":{"objective":"Permit pulls","confidence":"high","expected_effects":[],"must_preserve":[],"affected_boundaries":[],"ambiguities":[]}
		}`,
		"subject without repository": `{
			"schema_version":"adversary.outcome-context.v1","subject":{"provider":"github","pull_request":42},
			"sources":[{"kind":"pull_request_title","text":"Permit pulls"}],
			"intent":{"objective":"Permit pulls","confidence":"high","expected_effects":[],"must_preserve":[],"affected_boundaries":[],"ambiguities":[]}
		}`,
		"subject without provider": `{
			"schema_version":"adversary.outcome-context.v1","subject":{"repository":"acme/app","pull_request":42},
			"sources":[{"kind":"pull_request_title","text":"Permit pulls"}],
			"intent":{"objective":"Permit pulls","confidence":"high","expected_effects":[],"must_preserve":[],"affected_boundaries":[],"ambiguities":[]}
		}`,
		"unsupported provider": `{
			"schema_version":"adversary.outcome-context.v1","subject":{"provider":"gitlab","repository":"acme/app","pull_request":42},
			"sources":[{"kind":"pull_request_title","text":"Permit pulls"}],
			"intent":{"objective":"Permit pulls","confidence":"high","expected_effects":[],"must_preserve":[],"affected_boundaries":[],"ambiguities":[]}
		}`,
		"whitespace repository": `{
			"schema_version":"adversary.outcome-context.v1","subject":{"provider":"github","repository":"   ","pull_request":42},
			"sources":[{"kind":"pull_request_title","text":"Permit pulls"}],
			"intent":{"objective":"Permit pulls","confidence":"high","expected_effects":[],"must_preserve":[],"affected_boundaries":[],"ambiguities":[]}
		}`,
		"duplicate source kinds": `{
			"schema_version":"adversary.outcome-context.v1","subject":{"provider":"github","repository":"acme/app","pull_request":42},
			"sources":[{"kind":"pull_request_title","text":"one"},{"kind":"pull_request_title","text":"two"}],
			"intent":{"objective":"Permit pulls","confidence":"high","expected_effects":[],"must_preserve":[],"affected_boundaries":[],"ambiguities":[]}
		}`,
		"whitespace source": `{
			"schema_version":"adversary.outcome-context.v1","subject":{"provider":"github","repository":"acme/app","pull_request":42},
			"sources":[{"kind":"pull_request_title","text":"   "}],
			"intent":{"objective":"Permit pulls","confidence":"high","expected_effects":[],"must_preserve":[],"affected_boundaries":[],"ambiguities":[]}
		}`,
		"whitespace objective": `{
			"schema_version":"adversary.outcome-context.v1","subject":{"provider":"github","repository":"acme/app","pull_request":42},
			"sources":[{"kind":"pull_request_title","text":"Permit pulls"}],
			"intent":{"objective":"   ","confidence":"high","expected_effects":[],"must_preserve":[],"affected_boundaries":[],"ambiguities":[]}
		}`,
		"whitespace list item": `{
			"schema_version":"adversary.outcome-context.v1","subject":{"provider":"github","repository":"acme/app","pull_request":42},
			"sources":[{"kind":"pull_request_title","text":"Permit pulls"}],
			"intent":{"objective":"Permit pulls","confidence":"high","expected_effects":["   "],"must_preserve":[],"affected_boundaries":[],"ambiguities":[]}
		}`,
	}
	for name, fixture := range invalid {
		t.Run(name, func(t *testing.T) {
			var value any
			if err := json.Unmarshal([]byte(fixture), &value); err != nil {
				t.Fatal(err)
			}
			if err := compiled.Validate(value); err == nil {
				t.Fatal("schema accepted invalid fixture")
			}
		})
	}

	overlongSource := Context{
		SchemaVersion: SchemaVersion,
		Subject:       Subject{Provider: "github", Repository: "acme/app", PullRequest: 42},
		Sources:       []Source{{Kind: "pull_request_title", Text: strings.Repeat("x", MaxSourceCharacters+1)}},
		Intent: Intent{
			Objective:          "Permit pulls",
			Confidence:         "high",
			ExpectedEffects:    []string{},
			MustPreserve:       []string{},
			AffectedBoundaries: []string{},
			Ambiguities:        []string{},
		},
	}
	encoded, err := json.Marshal(overlongSource)
	if err != nil {
		t.Fatal(err)
	}
	var overlongValue any
	if err := json.Unmarshal(encoded, &overlongValue); err != nil {
		t.Fatal(err)
	}
	if err := compiled.Validate(overlongValue); err == nil {
		t.Fatalf("schema accepted source over %d characters", MaxSourceCharacters)
	}
}
