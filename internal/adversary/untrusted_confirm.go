package adversary

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"golang.org/x/term"
)

// isTerminal reports whether fd is a terminal. Overridable in tests.
var isTerminal = term.IsTerminal

type fdHolder interface {
	Fd() uintptr
}

// canPromptUntrustedConfirm is true when both stdin and stderr are TTYs so we
// can safely ask before host-executing an untrusted adversary.
func canPromptUntrustedConfirm(stdin io.Reader, stderr io.Writer) bool {
	in, okIn := stdin.(fdHolder)
	out, okOut := stderr.(fdHolder)
	if !okIn || !okOut {
		return false
	}
	return isTerminal(int(in.Fd())) && isTerminal(int(out.Fd()))
}

// confirmUntrustedHostExecution prompts on a TTY. Returns true only for y/yes.
func confirmUntrustedHostExecution(stdin io.Reader, stderr io.Writer, name, digest string) (bool, error) {
	fmt.Fprintf(stderr, "\nUntrusted adversary %q", name)
	if digest != "" {
		fmt.Fprintf(stderr, "\nDigest: %s", digest)
	}
	fmt.Fprintf(stderr, `

No valid official signature is available for this package. Host execution will
run unrestricted code with your user privileges (filesystem, network, etc.).

Run anyway? [y/N] `)

	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}
