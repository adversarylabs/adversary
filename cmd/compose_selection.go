package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/manifest"
	"github.com/adversarylabs/adversary/pkg/oci"
)

type composeContextProvider interface {
	composeSelectionContext(context.Context, *runOptions) (*detection.Context, error)
}

func (p processRuntime) composeSelectionContext(ctx context.Context, opts *runOptions) (*detection.Context, error) {
	resolved, _, err := p.resolveRunScope(ctx, application.AdversaryRunOptions{RepoPath: opts.path, BaseRef: opts.base, HeadRef: opts.head, AllFiles: opts.allFiles, ReviewContext: opts.reviewContext})
	if err != nil {
		return nil, err
	}
	files, ok := p.git.(internaladversary.RepositoryFileResolver)
	if !ok {
		return nil, nil
	}
	path := opts.path
	if path == "" {
		path = "."
	}
	paths, err := files.RepositoryFiles(ctx, path)
	if err != nil {
		// Whole-target reviews can operate outside Git. Missing inventory must not
		// turn a conservative optimization into a new run failure.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, nil
	}
	scope := detection.Context{RepositoryFiles: paths}
	if resolved.ReviewContext != nil {
		scope = *resolved.ReviewContext
		scope.RepositoryFiles = paths
		opts.reviewContext = resolved.ReviewContext
	}
	if resolved.AllFiles {
		for _, path := range paths {
			scope.ChangedFiles = append(scope.ChangedFiles, detection.ChangedFile{Path: path, Status: detection.StatusModified})
		}
	}
	return &scope, nil
}

type metadataRegistry interface {
	MetadataBatch(context.Context, []oci.Reference) map[string]oci.Metadata
}

func selectComposeRefs(ctx context.Context, app *application.App, opts *runOptions, refs []string, apiURL, profile string, resultOut, progress io.Writer) (application.ComposePlan, error) {
	var scope *detection.Context
	if provider, ok := app.Dependencies().Runtime.(composeContextProvider); ok {
		var err error
		scope, err = provider.composeSelectionContext(ctx, opts)
		if err != nil {
			return application.ComposePlan{}, err
		}
	}
	if apiURL == "" {
		apiURL = app.Dependencies().DefaultAPIURL
	}
	if profile == "" {
		profile = "default"
	}
	load := func(ctx context.Context, refs []string) (map[string]application.ComposeMetadata, error) {
		out := map[string]application.ComposeMetadata{}
		remote := []oci.Reference{}
		originals := map[string][]string{}
		for _, raw := range refs {
			ref := canonicalCatalogReference(raw)
			local := application.LocalComposeMetadata(ctx, app.Dependencies().Resolver, ref)
			if local.Error == nil {
				out[raw] = local
				continue
			}
			parsed, err := app.Dependencies().References.Parse(ref)
			if err != nil {
				out[raw] = local
				continue
			}
			if len(originals[parsed.Locator()]) == 0 {
				remote = append(remote, parsed)
			}
			originals[parsed.Locator()] = append(originals[parsed.Locator()], raw)
		}
		if len(remote) == 0 {
			return out, nil
		}
		fetched := map[string]oci.Metadata{}
		groups := map[string][]oci.Reference{}
		for _, ref := range remote {
			groups[ref.Registry] = append(groups[ref.Registry], ref)
		}
		for host, group := range groups {
			registry, err := app.Dependencies().Registries.New(apiURL, profile)
			if err != nil {
				return nil, fmt.Errorf("create registry client for %s: %w", host, err)
			}
			if host == "localhost" || hasLocalhostPort(host) {
				registry.SetPlainHTTP(true)
			}
			if metadata, ok := registry.(metadataRegistry); ok {
				for key, value := range metadata.MetadataBatch(ctx, group) {
					fetched[key] = value
				}
			}
		}
		for _, ref := range remote {
			raw := originals[ref.Locator()][0]
			item, ok := fetched[ref.Locator()]
			result := application.ComposeMetadata{Reference: raw, Error: fmt.Errorf("metadata unavailable")}
			if ok && item.Error == "" {
				result.Manifest, result.Error = manifest.Parse([]byte(item.Manifest))
				if result.Error == nil {
					pinned := ref
					pinned.Tag = ""
					pinned.Digest = item.Digest
					result.Reference = pinned.Locator()
				}
			}
			// Old publications may have no separate manifest. Preserve their graph
			// through the existing pull path; previews remain download-free.
			if result.Error != nil && !opts.composePlan {
				fmt.Fprintf(progress, "Compose: metadata unavailable for %s; loading legacy package\n", terminalSafeText(raw))
				if _, err := pullAdversary(ctx, canonicalCatalogReference(raw), apiURL, profile, app, progress); err == nil {
					result = application.LocalComposeMetadata(ctx, app.Dependencies().Resolver, canonicalCatalogReference(raw))
				}
			}
			for _, alias := range originals[ref.Locator()] {
				out[alias] = result
			}
		}
		return out, nil
	}
	plan, err := application.PlanCompose(ctx, refs, load, scope)
	if err != nil {
		return plan, err
	}
	if !opts.composePlan {
		for _, selection := range plan.Selections {
			state := "Skipped"
			if selection.Selected {
				state = "Selected"
			}
			fmt.Fprintf(progress, "%-8s %s — %s\n", state, terminalSafeText(selection.Reference), selection.Reason)
		}
	}
	if opts.composePlan {
		if opts.format == "json" {
			err = json.NewEncoder(resultOut).Encode(plan)
		} else {
			for _, s := range plan.Selections {
				state := "Skipped"
				if s.Selected {
					state = "Selected"
				}
				fmt.Fprintf(resultOut, "%-8s %s — %s\n", state, terminalSafeText(s.Reference), s.Reason)
			}
		}
		return plan, err
	}
	// All selection decisions are visible before the first selected payload pull.
	for _, selection := range plan.Selections {
		if !selection.Selected {
			continue
		}
		ref := selection.ResolvedReference
		local := application.LocalComposeMetadata(ctx, app.Dependencies().Resolver, ref)
		if local.Error != nil && selection.MetadataAvailable {
			if _, err := pullAdversary(ctx, ref, apiURL, profile, app, progress); err != nil {
				return plan, err
			}
		}
		if selection.Root {
			if dir := application.ComposePackageRoot(ctx, app.Dependencies().Resolver, ref); dir != "" {
				plan.VoiceRoots = append(plan.VoiceRoots, dir)
			}
		}
	}
	return plan, nil
}
