package cmd

import (
	"io"

	"github.com/spf13/cobra"
)

// NewRootCommand is a test-only compatibility helper. Production composition
// must always supply an explicit App through NewRootCommandWithApp.
func NewRootCommand(stdout, stderr io.Writer) *cobra.Command {
	app, err := newProcessApp(nilReader{}, stdout, stderr)
	if err != nil {
		panic(err)
	}
	return NewRootCommandWithApp(app)
}

type nilReader struct{}

func (nilReader) Read([]byte) (int, error) { return 0, io.EOF }
