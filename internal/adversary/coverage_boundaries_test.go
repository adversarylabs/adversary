package adversary

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func BenchmarkShouldRunForManyChangedFiles(b *testing.B) {
	patterns := []string{"cmd/**/*.go", "internal/**/*.go", "pkg/**/*.go", "docs/**/*.md", "schema/**/*.json", "templates/**/*.ts"}
	changed := make([]string, 20_000)
	for i := range changed {
		changed[i] = fmt.Sprintf("vendor/dependency-%05d/data.txt", i)
	}
	changed[len(changed)-1] = "pkg/review/review.go"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !ShouldRunForChangedFiles(patterns, changed, false) {
			b.Fatal("matching changed file was not detected")
		}
	}
}

func FuzzGlobMatcher(f *testing.F) {
	for _, seed := range [][2]string{
		{"**/*.go", "pkg/review/review.go"},
		{"docs/?.md", "docs/a.md"},
		{"[unterminated", "[unterminated"},
		{"", "README.md"},
		{"a\\b/**", "a/b/c"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, pattern, name string) {
		pattern = capFuzzString(pattern, 256)
		name = capFuzzString(name, 512)
		regex := globToRegexp(filepath.ToSlash(strings.TrimSpace(pattern)))
		_, compileErr := regexp.Compile(regex)
		got := globMatch(pattern, name)
		throughBoundary := ShouldRunForChangedFiles([]string{pattern}, []string{name}, false)
		if got != throughBoundary {
			t.Fatalf("globMatch=%t ShouldRunForChangedFiles=%t pattern=%q name=%q", got, throughBoundary, pattern, name)
		}
		if compileErr != nil && got {
			t.Fatalf("matcher accepted pattern whose translated regexp does not compile: %q", regex)
		}
	})
}

func capFuzzString(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
