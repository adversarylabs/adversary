package cmd

import (
	"context"
	"io"

	"github.com/adversarylabs/adversary/internal/application"
)

// expandComposeRefs expands adversary.yaml uses via the application port.
// When allowPull is false (e.g. --shell preflight), expansion never mutates the
// local store; missing members stay unresolved leaves.
func expandComposeRefs(
	ctx context.Context,
	app *application.App,
	refs []string,
	apiURL, profile string,
	noCompose bool,
	allowPull bool,
	progress io.Writer,
) (expanded []string, voiceRoots []string, err error) {
	if noCompose || len(refs) == 0 || app == nil {
		return refs, nil, nil
	}
	var pull application.ComposePullFunc
	if allowPull {
		pull = func(ctx context.Context, ref string) error {
			url, prof := apiURL, profile
			if url == "" {
				url = app.Dependencies().DefaultAPIURL
			}
			if prof == "" {
				prof = "default"
			}
			_, err := pullAdversary(ctx, ref, url, prof, app, progress)
			return err
		}
	}
	return application.ExpandCompose(ctx, app.Dependencies().Resolver, pull, refs, noCompose, progress)
}
