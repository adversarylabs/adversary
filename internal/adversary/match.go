package adversary

import (
	"path/filepath"
	"regexp"
	"strings"
)

func ShouldRunForChangedFiles(patterns, changedFiles []string, force bool) bool {
	if force || len(patterns) == 0 {
		return true
	}
	for _, file := range changedFiles {
		for _, pattern := range patterns {
			if globMatch(pattern, file) {
				return true
			}
		}
	}
	return false
}

func globMatch(pattern, name string) bool {
	pattern = filepath.ToSlash(strings.TrimSpace(pattern))
	name = filepath.ToSlash(strings.TrimSpace(name))
	if pattern == "" || name == "" {
		return false
	}

	regex := globToRegexp(pattern)
	return regexp.MustCompile(regex).MatchString(name)
}

func globToRegexp(pattern string) string {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		switch ch {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					i++
					b.WriteString("(?:.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '.', '+', '(', ')', '|', '[', ']', '{', '}', '^', '$', '\\':
			b.WriteByte('\\')
			b.WriteByte(ch)
		default:
			b.WriteByte(ch)
		}
	}
	b.WriteString("$")
	return b.String()
}
