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
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		pattern = filepath.ToSlash(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		re, err := regexp.Compile(globToRegexp(pattern))
		if err != nil {
			continue
		}
		compiled = append(compiled, re)
	}
	for _, file := range changedFiles {
		name := filepath.ToSlash(file)
		for _, pattern := range compiled {
			if name != "" && pattern.MatchString(name) {
				return true
			}
		}
	}
	return false
}

func globMatch(pattern, name string) bool {
	pattern = filepath.ToSlash(strings.TrimSpace(pattern))
	name = filepath.ToSlash(name)
	if pattern == "" || name == "" {
		return false
	}

	regex := globToRegexp(pattern)
	re, err := regexp.Compile(regex)
	return err == nil && re.MatchString(name)
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
