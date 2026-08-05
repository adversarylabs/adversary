package workspace

import "strings"

// AuthorAllowed reports whether a review comment author may count as gold.
// Built-in bot rejection is separate (scope package); this applies config filters.
// Empty AuthorsOnly = all non-ignored humans; ignore always wins over only.
func AuthorAllowed(login string, authorsOnly, authorsIgnore []string) bool {
	login = strings.ToLower(strings.TrimSpace(login))
	if login == "" {
		return false
	}
	for _, ig := range authorsIgnore {
		if login == strings.ToLower(strings.TrimSpace(ig)) {
			return false
		}
	}
	if len(authorsOnly) == 0 {
		return true
	}
	for _, only := range authorsOnly {
		if login == strings.ToLower(strings.TrimSpace(only)) {
			return true
		}
	}
	return false
}

// FilterAuthor applies SourcesConfig author rules.
func (c Config) FilterAuthor(login string) bool {
	return AuthorAllowed(login, c.Sources.AuthorsOnly, c.Sources.AuthorsIgnore)
}
