package pipeline

import (
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/train/adversaries"
	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/scope"
)

func TestGoDatabaseCycleRoutesGloballyButAdmitsOnlyDatabaseGold(t *testing.T) {
	discovered := []adversaries.Package{
		{
			ID: "go-cli", ManifestName: "go/cli",
			ScopeMarkdown: "Review Go CLI commands, flags, output, and persisted command history behavior.",
		},
		{
			ID: "go-concurrency", ManifestName: "go/concurrency",
			ScopeMarkdown: "Review Go concurrency races, goroutine lifecycle, mutexes, and channels.",
		},
		{
			ID: "go-database", ManifestName: "go/database",
			ScopeMarkdown: "Review Go database queries, transactions, migrations, rows, and connection pools.",
		},
	}
	training, _, matched := adversaries.ResolveTrainingPackages(discovered, []string{"go-database"}, nil)
	if !matched || len(training) != 1 || training[0].ID != "go-database" {
		t.Fatalf("unexpected training selection: matched=%v packages=%v", matched, packageIDs(training))
	}
	routing, _ := routingPackagesForTraining(discovered, training, nil)
	if got := strings.Join(packageIDs(routing), ","); got != "go-cli,go-concurrency,go-database" {
		t.Fatalf("target selection narrowed routing candidates: %s", got)
	}
	router := &scope.Router{Candidates: routerCandidates(routing), UseLLM: false}

	wrongRoute := router.RouteComment(
		"Two goroutines can write the CLI IP history map concurrently here; this is a data race.",
		"cmd/docker/history.go", "reviewer",
	)
	if wrongRoute.Decision != scope.InScope || wrongRoute.OwnerID != "go-concurrency" {
		t.Fatalf("CLI/IP-history race was forced into database: %+v", wrongRoute)
	}
	wrongCase := caseWithRoutedConcern("wrong-owner", wrongRoute)
	restrictGoldToTrainingTarget(wrongCase, "go-database")
	if got := len(cases.ApprovedLabels(wrongCase.Labels.ExpectedConcerns)); got != 0 {
		t.Fatalf("sibling-owned concern remained target gold: %+v", wrongCase.Labels.ExpectedConcerns)
	}
	wrongLabel := wrongCase.Labels.ExpectedConcerns[0]
	if wrongLabel.OwnerAdversary != "go-concurrency" || wrongLabel.Scope != "out_of_scope" || wrongLabel.Approved {
		t.Fatalf("sibling ownership was not preserved as non-target evidence: %+v", wrongLabel)
	}

	out := &huntOutcome{}
	wrongResult := collectResult{
		kept:      []*cases.Case{wrongCase},
		inScopeN:  len(cases.ApprovedLabels(wrongCase.Labels.ExpectedConcerns)),
		outScopeN: len(cases.OutOfScopeLabels(wrongCase.Labels.ExpectedConcerns)),
	}
	if applyCollectResult(out, wrongResult, false, 1) || out.prsWithInScope != 0 {
		t.Fatalf("wrong-owner concern stopped target discovery: %+v", out)
	}

	databaseRoute := router.RouteComment(
		"Not closing db.QueryContext rows on this error path creates a database resource leak and will exhaust the connection pool.",
		"internal/store/query.go", "reviewer",
	)
	if databaseRoute.Decision != scope.InScope || databaseRoute.OwnerID != "go-database" {
		t.Fatalf("true database concern was not routed to database: %+v", databaseRoute)
	}
	databaseCase := caseWithRoutedConcern("database-owner", databaseRoute)
	restrictGoldToTrainingTarget(databaseCase, "go-database")
	databaseResult := collectResult{
		kept:      []*cases.Case{databaseCase},
		inScopeN:  len(cases.ApprovedLabels(databaseCase.Labels.ExpectedConcerns)),
		outScopeN: len(cases.OutOfScopeLabels(databaseCase.Labels.ExpectedConcerns)),
	}
	if !applyCollectResult(out, databaseResult, false, 1) {
		t.Fatal("database-owned concern did not satisfy the database cycle")
	}
	if out.prsWithInScope != 1 || len(out.caseList) != 1 || out.caseList[0].ID != "database-owner" {
		t.Fatalf("target admission kept the wrong cases: %+v", out)
	}
}

func TestRoutingPackagesPreferSelectedDuplicateCheckout(t *testing.T) {
	canonical := adversaries.Package{Dir: "/work/go-database-adversary", DirName: "go-database-adversary", ID: "go-database", ManifestName: "go/database"}
	override := adversaries.Package{Dir: "/work/database-experiment", DirName: "database-experiment", ID: "database-experiment", ManifestName: "go/database"}
	discovered := []adversaries.Package{canonical, override}
	training, _, matched := adversaries.ResolveTrainingPackages(discovered, []string{"database-experiment"}, nil)
	if !matched || len(training) != 1 {
		t.Fatalf("explicit checkout did not select: matched=%v packages=%v", matched, packageIDs(training))
	}
	routing, duplicates := routingPackagesForTraining(discovered, training, nil)
	if len(routing) != 1 || routing[0].Dir != override.Dir {
		t.Fatalf("routing ignored selected local override: %+v", routing)
	}
	if len(duplicates) != 1 || duplicates[0].Kept.Dir != override.Dir || duplicates[0].Ignored.Dir != canonical.Dir {
		t.Fatalf("duplicate report disagrees with routing checkout: %+v", duplicates)
	}
}

func TestExplicitSingleTargetRejectsSiblingOwnedGold(t *testing.T) {
	opts := Options{AdversaryName: "go-project", TrainOnlyIDs: []string{"go-project"}}
	training := []adversaries.Package{{ID: "go-project", ManifestName: "go/project"}}
	opts.targetAdversaryOnly = len(training) == 1

	c := caseWithRoutedConcern("concurrency-owner", scope.Route{
		Decision: scope.InScope,
		OwnerID:  "go-concurrency",
		Reason:   "shared informer lifecycle concern",
		Method:   "llm",
	})
	restrictGoldToSelectedTarget(opts, []*cases.Case{c})
	if got := len(cases.ApprovedLabels(c.Labels.ExpectedConcerns)); got != 0 {
		t.Fatalf("sibling-owned concern satisfied explicit target hunt: %+v", c.Labels.ExpectedConcerns)
	}

	unrestricted := caseWithRoutedConcern("all-packages", scope.Route{
		Decision: scope.InScope,
		OwnerID:  "go-concurrency",
	})
	restrictGoldToSelectedTarget(Options{AdversaryName: "go-project"}, []*cases.Case{unrestricted})
	if got := len(cases.ApprovedLabels(unrestricted.Labels.ExpectedConcerns)); got != 1 {
		t.Fatalf("all-package training unexpectedly discarded sibling gold: %+v", unrestricted.Labels.ExpectedConcerns)
	}
}

func caseWithRoutedConcern(id string, route scope.Route) *cases.Case {
	return &cases.Case{
		ID: id,
		Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{{
			ID:             id + "-concern",
			Summary:        "review concern",
			Approved:       route.Decision == scope.InScope,
			Scope:          string(route.Decision),
			ScopeReason:    route.Reason,
			ScopeMethod:    route.Method,
			OwnerAdversary: route.OwnerID,
		}}},
	}
}
