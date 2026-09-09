// Package progress controls human-readable CLI progress output.
package progress

import (
	"io"
	"os"
	"strings"
)

// InCI reports whether CI requests concise progress. Empty, false, and 0
// preserve local output; other nonempty values enable CI output.
func InCI() bool {
	value := strings.TrimSpace(os.Getenv("CI"))
	return value != "" && value != "0" && !strings.EqualFold(value, "false")
}

// Detail suppresses routine progress in CI. Warnings and errors should use
// the original writer so diagnostics remain visible.
func Detail(w io.Writer) io.Writer {
	if w == nil || InCI() {
		return io.Discard
	}
	return w
}
