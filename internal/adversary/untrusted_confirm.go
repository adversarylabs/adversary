package adversary

import (
	"bufio"
	"context"
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
// Respects ctx cancellation (e.g. Ctrl+C via signal.NotifyContext) so interrupt
// exits the prompt instead of hanging on ReadString.
func confirmUntrustedHostExecution(ctx context.Context, stdin io.Reader, stderr io.Writer, name, digest string) (bool, error) {
	fmt.Fprintf(stderr, "\nUntrusted adversary %q", name)
	if digest != "" {
		fmt.Fprintf(stderr, "\nDigest: %s", digest)
	}
	fmt.Fprintf(stderr, `

No valid artifact signature is available for this package. Host execution will
run unrestricted code with your user privileges (filesystem, network, etc.).

Run anyway? [y/N] `)

	type readResult struct {
		line string
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		ch <- readResult{line: line, err: err}
	}()

	select {
	case <-ctx.Done():
		fmt.Fprintln(stderr) // move past the prompt line on interrupt
		return false, ctx.Err()
	case r := <-ch:
		if r.err != nil && r.err != io.EOF {
			return false, fmt.Errorf("read confirmation: %w", r.err)
		}
		answer := strings.ToLower(strings.TrimSpace(r.line))
		return answer == "y" || answer == "yes", nil
	}
}
