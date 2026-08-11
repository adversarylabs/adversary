package results

import (
	"context"
	"errors"
	"fmt"
)

// AutoIssueOptions controls issue creation for one completed train run.
type AutoIssueOptions struct {
	Context        context.Context
	ResolvePackage func(packageID string) (string, error)
	IssueClient    IssueClient
}

// AutoIssueRun opens deduplicated issues for actionable aggregate results from
// runID. Individual misses and ungraded human rows deliberately remain local.
func AutoIssueRun(stateRoot, runID string, opts AutoIssueOptions) ([]ApplyResult, error) {
	if opts.ResolvePackage == nil {
		return nil, fmt.Errorf("package resolver required")
	}
	rows, err := List(stateRoot, "", StatusNew)
	if err != nil {
		return nil, err
	}
	var applied []ApplyResult
	for _, row := range rows {
		if row.RunID != runID {
			continue
		}
		kind := normalizeKind(row.Kind)
		if kind != KindDraft && kind != KindFalsePositive {
			continue
		}
		packagePath, err := opts.ResolvePackage(row.Package)
		if err != nil {
			return applied, fmt.Errorf("resolve package %q for result %s: %w", row.Package, row.ID, err)
		}
		result, err := Apply(stateRoot, row.ID, ApplyOptions{
			PackagePath: packagePath,
			CreateIssue: true,
			SkipDraft:   true,
			IssueClient: opts.IssueClient,
			Context:     opts.Context,
		})
		if errors.Is(err, ErrResultDismissed) {
			continue
		}
		if err != nil {
			return applied, fmt.Errorf("result %s: %w", row.ID, err)
		}
		applied = append(applied, result)
	}
	return applied, nil
}
