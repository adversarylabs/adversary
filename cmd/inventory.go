package cmd

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/repository"
)

// inventoryItem is one adversary visible through list/search (local store and/or remote catalog).
type inventoryItem struct {
	Name        string
	Version     string
	Description string
	Reference   string
	Source      string // "local" or "remote"
	Digest      string // local only when known
}

func collectInventory(
	ctx context.Context,
	app *application.App,
	apiURL, profile, query string,
	stderr io.Writer,
) ([]inventoryItem, error) {
	query = strings.TrimSpace(query)
	deps := app.Dependencies()

	localEntries, err := deps.Resolver.Entries(10000)
	if err != nil {
		return nil, err
	}

	items := make([]inventoryItem, 0, len(localEntries)+32)
	for _, entry := range localEntries {
		item := inventoryItem{
			Name:      entry.Record.Name,
			Version:   entry.Record.Version,
			Reference: entry.CanonicalReference,
			Source:    "local",
			Digest:    entry.Digest,
		}
		if matchesInventoryQuery(item, query) {
			items = append(items, item)
		}
	}

	remote, remoteErr := fetchRemoteInventory(ctx, deps, apiURL, profile, query)
	if remoteErr != nil {
		// Local inventory must still work offline or without login.
		if stderr != nil {
			fmt.Fprintf(stderr, "Warning: remote catalog unavailable (%v); showing local adversaries only.\n", remoteErr)
		}
	} else {
		items = append(items, remote...)
	}

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Name != items[j].Name {
			return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
		}
		if items[i].Version != items[j].Version {
			return items[i].Version < items[j].Version
		}
		if items[i].Source != items[j].Source {
			// local before remote for the same name/version
			return items[i].Source == "local"
		}
		return items[i].Reference < items[j].Reference
	})
	return items, nil
}

func fetchRemoteInventory(
	ctx context.Context,
	deps application.Dependencies,
	apiURL, profile, query string,
) ([]inventoryItem, error) {
	store := deps.Auth
	var token string
	auth, ok, err := scopedAuth(store, apiURL, profile, deps.RegistryHost)
	if err != nil {
		return nil, err
	}
	if ok {
		token = auth.Token
	}
	client := deps.API.New(apiURL)
	results, err := client.Search(ctx, query, token)
	if err != nil {
		return nil, err
	}
	items := make([]inventoryItem, 0, len(results))
	for _, r := range results {
		ref := r.Reference
		if ref == "" {
			ref = r.Name
		}
		name := r.Name
		if name == "" {
			name = ref
		}
		// Remote search is already filtered by the API when a query is provided.
		items = append(items, inventoryItem{
			Name:        name,
			Version:     r.Version,
			Description: r.Description,
			Reference:   ref,
			Source:      "remote",
		})
	}
	return items, nil
}

func matchesInventoryQuery(item inventoryItem, query string) bool {
	if query == "" {
		return true
	}
	q := strings.ToLower(query)
	fields := []string{item.Name, item.Version, item.Description, item.Reference, item.Digest, item.Source}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), q) {
			return true
		}
	}
	return false
}

func writeInventoryText(w io.Writer, items []inventoryItem) error {
	if len(items) == 0 {
		fmt.Fprintln(w, "No adversaries found.")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tVERSION\tSOURCE\tREFERENCE\tDESCRIPTION")
	for _, item := range items {
		name := item.Name
		if name == "" {
			name = item.Reference
		}
		desc := item.Description
		if desc == "" && item.Digest != "" {
			desc = shortDigest(item.Digest)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			sanitizeCell(name),
			sanitizeCell(item.Version),
			sanitizeCell(item.Source),
			sanitizeCell(item.Reference),
			sanitizeCell(desc),
		)
	}
	return tw.Flush()
}

func inventoryToSearchDTOs(items []inventoryItem) []searchResultDTO {
	out := make([]searchResultDTO, 0, len(items))
	for _, item := range items {
		out = append(out, searchResultDTO{
			Name:        item.Name,
			Version:     item.Version,
			Description: item.Description,
			Reference:   item.Reference,
			Source:      item.Source,
			Digest:      item.Digest,
		})
	}
	return out
}

// localArtifactsForListJSON builds the detailed local artifact payload retained for list --format json.
func localArtifactsForListJSON(app *application.App, entries []repository.Entry) ([]artifactDTO, error) {
	items := make([]artifactDTO, 0, len(entries))
	for _, e := range entries {
		files, err := app.Dependencies().Resolver.Inventory(e.Record)
		if err != nil {
			return nil, fmt.Errorf("read stored artifact inventory for %s: %w", e.CanonicalReference, err)
		}
		items = append(items, storedArtifactDTOWithFiles(e.CanonicalReference, e.Digest, e.Record, files))
	}
	return items, nil
}
