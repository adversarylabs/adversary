package cmd

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/manifest"
	"github.com/adversarylabs/adversary/pkg/repository"
)

// Official registry host for retired-path filtering (matches oci.DefaultRegistry).
const officialRegistryHost = "registry.adversarylabs.ai"

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
			Name:        entry.Record.Name,
			Version:     entry.Record.Version,
			Description: localDescription(deps.Resolver, entry.Record),
			Reference:   entry.CanonicalReference,
			Source:      "local",
			Digest:      entry.Digest,
		}
		if isRetiredPublisherInventory(item) {
			continue
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
		for _, item := range remote {
			if isRetiredPublisherInventory(item) {
				continue
			}
			items = append(items, item)
		}
	}

	// Search/list are a package catalog surface: one row per adversary name
	// (newest version). Historical local store versions stay available by
	// explicit reference for pull/run.
	items = collapseInventoryToLatest(items)

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Name != items[j].Name {
			return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
		}
		if items[i].Source != items[j].Source {
			// local before remote for the same name
			return items[i].Source == "local"
		}
		return items[i].Reference < items[j].Reference
	})
	return items, nil
}

// collapseInventoryToLatest keeps one inventory row per package name (case-
// insensitive). Higher semver wins; when versions tie, prefer remote (catalog)
// so discovery points at the registry path rather than a stale local alias.
func collapseInventoryToLatest(items []inventoryItem) []inventoryItem {
	if len(items) < 2 {
		return items
	}
	best := make(map[string]inventoryItem, len(items))
	order := make([]string, 0, len(items))
	for _, item := range items {
		key := inventoryNameKey(item)
		cur, ok := best[key]
		if !ok {
			best[key] = item
			order = append(order, key)
			continue
		}
		if preferInventoryItem(item, cur) {
			best[key] = item
		}
	}
	out := make([]inventoryItem, 0, len(best))
	for _, key := range order {
		out = append(out, best[key])
	}
	return out
}

func inventoryNameKey(item inventoryItem) string {
	name := strings.ToLower(strings.TrimSpace(item.Name))
	if name != "" {
		return name
	}
	return strings.ToLower(strings.TrimSpace(item.Reference))
}

// isRetiredPublisherInventory reports whether an entry is a retired official-
// registry path that the free catalog no longer publishes:
//   - registry.adversarylabs.ai/adversarylabs/<name> (old publisher namespace)
//   - registry.adversarylabs.ai/library/<flat-name> when the package name is
//     flat (go-cli, secrets). Multi-segment names (go/cli, local/tool) stay
//     visible so local packs of domain/dev adversaries still appear.
// Domain catalog refs and non-official registries (localhost, GHCR, …) stay.
func isRetiredPublisherInventory(item inventoryItem) bool {
	name := strings.ToLower(strings.TrimSpace(item.Name))
	if strings.HasPrefix(name, "adversarylabs/") {
		return true
	}

	host, repo, ok := splitInventoryReference(item.Reference)
	if !ok {
		return false
	}
	if host != officialRegistryHost {
		return false
	}
	ns, rest, hasRest := strings.Cut(repo, "/")
	switch ns {
	case "adversarylabs":
		return true
	case "library":
		if !hasRest || rest == "" {
			return true
		}
		// Flat short-name pack path for a flat package name → retired catalog shape.
		if name == "" || !strings.Contains(name, "/") {
			return true
		}
		return false
	default:
		return false
	}
}

// splitInventoryReference extracts host and repository path from an OCI-ish
// reference without importing pkg/oci (cmd handlers must not call it directly).
func splitInventoryReference(value string) (host, repository string, ok bool) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" || strings.Contains(value, "://") {
		return "", "", false
	}
	// Strip digest / tag for path inspection.
	if at := strings.Index(value, "@"); at >= 0 {
		value = value[:at]
	}
	// Tag is after the last colon only when it is not a port (host:port/...).
	if colon := strings.LastIndex(value, ":"); colon >= 0 {
		slash := strings.LastIndex(value, "/")
		if colon > slash {
			value = value[:colon]
		}
	}
	parts := strings.Split(value, "/")
	if len(parts) < 2 {
		return "", "", false
	}
	first := parts[0]
	if !(strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost") {
		return "", "", false
	}
	return first, strings.Join(parts[1:], "/"), true
}

func preferInventoryItem(candidate, current inventoryItem) bool {
	if preferCatalogVersion(candidate.Version, current.Version) {
		return true
	}
	if preferCatalogVersion(current.Version, candidate.Version) {
		return false
	}
	// Same (or incomparable) version: prefer remote catalog over local store.
	if candidate.Source != current.Source {
		return candidate.Source == "remote"
	}
	return candidate.Reference < current.Reference
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

// localDescription reads the packed adversary.yaml description for a stored record.
// Failures are non-fatal so list/search still works for damaged or incomplete installs.
func localDescription(resolver application.Resolver, rec repository.Record) string {
	if resolver == nil {
		return ""
	}
	lease, err := resolver.PayloadSources(rec)
	if err != nil || lease == nil {
		return ""
	}
	defer func() { _ = lease.Close() }()
	if lease.AdversaryManifest == nil {
		return ""
	}
	reader, err := lease.AdversaryManifest.Open()
	if err != nil {
		return ""
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, manifest.MaxSize))
	if err != nil || len(data) == 0 {
		return ""
	}
	parsed, err := manifest.Parse(data)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(parsed.Description)
}
