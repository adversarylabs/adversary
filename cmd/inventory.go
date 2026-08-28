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

// Origin of a raw inventory row before status merge.
const (
	inventoryOriginLocal  = "local"
	inventoryOriginRemote = "remote"
)

// User-facing inventory status after merging local store + remote catalog.
const (
	inventoryStatusInstalled = "installed"
	inventoryStatusCatalog   = "catalog"
	inventoryStatusOutdated  = "outdated"
)

// inventoryItem is one adversary visible through list/search (local store and/or remote catalog).
type inventoryItem struct {
	Name          string
	Version       string // installed version when present; else catalog version
	LatestVersion string // catalog version when known and newer (outdated)
	Description   string
	Reference     string
	// Source is the raw origin before merge ("local"/"remote"), and after merge
	// remains "local" for installed/outdated and "remote" for catalog-only
	// (backward compatible JSON field).
	Source string
	// Status is installed | catalog | outdated.
	Status string
	Digest string // local only when known
}

// inventoryScope selects which status rows to show after merge.
// At most one of Installed, Catalog, Outdated may be true; all false means all.
type inventoryScope struct {
	Installed bool // installed + outdated
	Catalog   bool // catalog-only (not installed)
	Outdated  bool // outdated only
}

func (s inventoryScope) validate() error {
	n := 0
	if s.Installed {
		n++
	}
	if s.Catalog {
		n++
	}
	if s.Outdated {
		n++
	}
	if n > 1 {
		return fmt.Errorf("use only one of --installed, --catalog, and --outdated")
	}
	return nil
}

func (s inventoryScope) allows(status string) bool {
	switch {
	case s.Outdated:
		return status == inventoryStatusOutdated
	case s.Installed:
		return status == inventoryStatusInstalled || status == inventoryStatusOutdated
	case s.Catalog:
		return status == inventoryStatusCatalog
	default:
		return true
	}
}

func collectInventory(
	ctx context.Context,
	app *application.App,
	apiURL, profile, query string,
	stderr io.Writer,
	scope inventoryScope,
) ([]inventoryItem, error) {
	if err := scope.validate(); err != nil {
		return nil, err
	}
	query = strings.TrimSpace(query)
	deps := app.Dependencies()

	localEntries, err := deps.Resolver.Entries(10000)
	if err != nil {
		return nil, err
	}

	// Include every non-retired local install before merging. Filtering on the
	// query here would drop rows that only match after merge (status, latestVersion).
	raw := make([]inventoryItem, 0, len(localEntries)+32)
	for _, entry := range localEntries {
		item := inventoryItem{
			Name:        entry.Record.Name,
			Version:     entry.Record.Version,
			Description: localDescription(deps.Resolver, entry.Record),
			Reference:   entry.CanonicalReference,
			Source:      inventoryOriginLocal,
			Digest:      entry.Digest,
		}
		if isRetiredPublisherInventory(item) {
			continue
		}
		raw = append(raw, item)
	}

	// Always fetch the full remote catalog (empty API q). Pre-filtering remote by
	// query would omit packages that only match via status/latestVersion once
	// combined with local installs; client-side matchesInventoryQuery runs after merge.
	remote, remoteErr := fetchRemoteInventory(ctx, deps, apiURL, profile, "")
	if remoteErr != nil {
		// Local inventory must still work offline or without login.
		// Without remote we cannot mark outdated; installed rows stay "installed".
		if stderr != nil {
			fmt.Fprintf(stderr, "Warning: remote catalog unavailable (%v); showing local adversaries only.\n", remoteErr)
		}
	} else {
		for _, item := range remote {
			if isRetiredPublisherInventory(item) {
				continue
			}
			raw = append(raw, item)
		}
	}

	// One row per package name with status: installed | catalog | outdated.
	// Query and scope filters apply only after status is computed.
	items := mergeInventoryByName(raw)
	filtered := make([]inventoryItem, 0, len(items))
	for _, item := range items {
		if !scope.allows(item.Status) {
			continue
		}
		if matchesInventoryQuery(item, query) {
			filtered = append(filtered, item)
		}
	}
	items = filtered

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Name != items[j].Name {
			return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
		}
		if items[i].Status != items[j].Status {
			return inventoryStatusRank(items[i].Status) < inventoryStatusRank(items[j].Status)
		}
		return items[i].Reference < items[j].Reference
	})
	return items, nil
}

func inventoryStatusRank(status string) int {
	switch status {
	case inventoryStatusOutdated:
		return 0
	case inventoryStatusInstalled:
		return 1
	case inventoryStatusCatalog:
		return 2
	default:
		return 3
	}
}

// mergeInventoryByName keeps one inventory row per package name. When both a
// local install and a catalog entry exist, status is installed (current or
// newer than catalog) or outdated (catalog has a higher version).
func mergeInventoryByName(items []inventoryItem) []inventoryItem {
	type pair struct {
		local  *inventoryItem
		remote *inventoryItem
	}
	best := make(map[string]*pair, len(items))
	order := make([]string, 0, len(items))

	for i := range items {
		item := items[i]
		key := inventoryNameKey(item)
		p, ok := best[key]
		if !ok {
			p = &pair{}
			best[key] = p
			order = append(order, key)
		}
		switch item.Source {
		case inventoryOriginRemote:
			if p.remote == nil || preferRawInventoryItem(item, *p.remote) {
				cp := item
				p.remote = &cp
			}
		default:
			if p.local == nil || preferRawInventoryItem(item, *p.local) {
				cp := item
				p.local = &cp
			}
		}
	}

	out := make([]inventoryItem, 0, len(best))
	for _, key := range order {
		out = append(out, composeInventoryStatus(best[key].local, best[key].remote))
	}
	return out
}

func composeInventoryStatus(local, remote *inventoryItem) inventoryItem {
	switch {
	case local != nil && remote != nil:
		name := firstNonEmpty(local.Name, remote.Name)
		desc := firstNonEmpty(local.Description, remote.Description)
		// Prefer catalog reference so pull/upgrade targets the registry path.
		ref := firstNonEmpty(remote.Reference, local.Reference)
		if preferCatalogVersion(remote.Version, local.Version) {
			return inventoryItem{
				Name:          name,
				Version:       local.Version,
				LatestVersion: remote.Version,
				Description:   desc,
				Reference:     ref,
				Source:        inventoryOriginLocal,
				Status:        inventoryStatusOutdated,
				Digest:        local.Digest,
			}
		}
		return inventoryItem{
			Name:        name,
			Version:     local.Version,
			Description: desc,
			Reference:   ref,
			Source:      inventoryOriginLocal,
			Status:      inventoryStatusInstalled,
			Digest:      local.Digest,
		}
	case local != nil:
		return inventoryItem{
			Name:        local.Name,
			Version:     local.Version,
			Description: local.Description,
			Reference:   local.Reference,
			Source:      inventoryOriginLocal,
			Status:      inventoryStatusInstalled,
			Digest:      local.Digest,
		}
	default:
		return inventoryItem{
			Name:        remote.Name,
			Version:     remote.Version,
			Description: remote.Description,
			Reference:   remote.Reference,
			Source:      inventoryOriginRemote,
			Status:      inventoryStatusCatalog,
		}
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// preferRawInventoryItem chooses the better row of the same origin (local or remote).
func preferRawInventoryItem(candidate, current inventoryItem) bool {
	if preferCatalogVersion(candidate.Version, current.Version) {
		return true
	}
	if preferCatalogVersion(current.Version, candidate.Version) {
		return false
	}
	return candidate.Reference < current.Reference
}

// collapseInventoryToLatest is retained for tests that exercise per-name version
// selection among homogeneous rows; production list/search uses mergeInventoryByName.
func collapseInventoryToLatest(items []inventoryItem) []inventoryItem {
	return mergeInventoryByName(items)
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
//
// Team-owned adversarylabs/* source packages stay hidden from the catalog
// inventory. Promoted library/* packages are canonical catalog entries.
//
// Domain catalog refs and non-official registries (localhost, GHCR, …) stay.
func isRetiredPublisherInventory(item inventoryItem) bool {
	name := strings.ToLower(strings.TrimSpace(item.Name))
	host, repo, ok := splitInventoryReference(item.Reference)
	if ok && host == officialRegistryHost {
		ns, rest, hasRest := strings.Cut(repo, "/")
		if ns == "library" {
			return !hasRest || rest == ""
		}
		if ns == "adversarylabs" {
			return true
		}
	}
	if strings.HasPrefix(name, "adversarylabs/") {
		return true
	}
	return false
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
			Source:      inventoryOriginRemote,
		})
	}
	return items, nil
}

func matchesInventoryQuery(item inventoryItem, query string) bool {
	if query == "" {
		return true
	}
	q := strings.ToLower(query)
	fields := []string{
		item.Name,
		item.Version,
		item.LatestVersion,
		item.Description,
		item.Reference,
		item.Digest,
		item.Source,
		item.Status,
	}
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
	fmt.Fprintln(tw, "NAME\tVERSION\tLATEST\tSTATUS\tREFERENCE\tDESCRIPTION")
	for _, item := range items {
		name := item.Name
		if name == "" {
			name = item.Reference
		}
		desc := item.Description
		if desc == "" && item.Digest != "" {
			desc = shortDigest(item.Digest)
		}
		latest := item.LatestVersion
		if latest == "" {
			latest = "-"
		}
		status := item.Status
		if status == "" {
			// Fallback for incomplete rows.
			if item.Source == inventoryOriginRemote {
				status = inventoryStatusCatalog
			} else {
				status = inventoryStatusInstalled
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			sanitizeCell(name),
			sanitizeCell(item.Version),
			sanitizeCell(latest),
			sanitizeCell(status),
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
			Name:          item.Name,
			Version:       item.Version,
			LatestVersion: item.LatestVersion,
			Description:   item.Description,
			Reference:     item.Reference,
			Status:        item.Status,
			Source:        item.Source,
			Digest:        item.Digest,
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
