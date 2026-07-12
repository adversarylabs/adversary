package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/spf13/cobra"
)

type inspectOptions struct {
	json   bool
	format string
	files  bool
}

func newInspectCommand(app *application.App) *cobra.Command {
	opts := &runOptions{}
	inspectOpts := &inspectOptions{}

	cmd := &cobra.Command{
		Use:   "inspect <name|digest|adversary-ref>",
		Short: "Inspect a locally stored adversary or local runtime configuration",
		Example: `  adversary inspect ./smoke-tests/comment-sentence-adversary --repo .
  adversary inspect security-reviewer --repo .
  adversary inspect security-reviewer
  adversary inspect security-reviewer:0.1.0
  adversary inspect sha256:abc123`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := commandFormat(cmd, inspectOpts.format, inspectOpts.json)
			if err != nil {
				return err
			}
			if inspectOpts.json {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning: --json is deprecated; use --format json.")
			}
			deps := app.Dependencies()
			resolution, lookupErr := deps.Resolver.Lookup(cmd.Context(), args[0])
			if lookupErr == nil && !resolution.Local {
				if format == "json" {
					if inspectOpts.json {
						return json.NewEncoder(cmd.OutOrStdout()).Encode(legacyArtifact(resolution.CanonicalReference, resolution.Digest, resolution.Record))
					}
					files, err := deps.Resolver.Inventory(resolution.Record)
					if err != nil {
						return fmt.Errorf("read stored artifact inventory: %w", err)
					}
					return writeJSONVersion(cmd.OutOrStdout(), 2, "inspect", storedArtifactDTOWithFiles(resolution.CanonicalReference, resolution.Digest, resolution.Record, files))
				}
				var files []pack.File
				if inspectOpts.files {
					files, err = deps.Resolver.Inventory(resolution.Record)
					if err != nil {
						return fmt.Errorf("read stored artifact inventory: %w", err)
					}
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Canonical reference: %s\nDigest: %s\nName: %s\nVersion: %s\n", resolution.CanonicalReference, resolution.Digest, resolution.Record.Name, resolution.Record.Version)
				if inspectOpts.files {
					fmt.Fprintln(cmd.OutOrStdout(), "Files:")
					for _, f := range files {
						fmt.Fprintf(cmd.OutOrStdout(), "  %s  %d bytes  sha256:%s  mode %#o\n", f.Path, f.Size, f.SHA256, f.Mode)
					}
				}
				return nil
			}
			if lookupErr != nil && !errors.Is(lookupErr, internaladversary.ErrNotFound) {
				return lookupErr
			}
			if format == "json" {
				if inspectOpts.json {
					return fmt.Errorf("--json is only supported for locally stored adversaries")
				}
				return fmt.Errorf("JSON inspect describes stored artifacts; local execution-plan inspection supports --format text only")
			}
			return deps.Runtime.Inspect(cmd.Context(), application.AdversaryRunOptions{
				AdversaryRef: args[0],
				RepoPath:     opts.repo,
				NoNetwork:    opts.noNetwork,
				Stdout:       cmd.OutOrStdout(),
				Stderr:       cmd.ErrOrStderr(),
			})
		},
	}

	cmd.Flags().StringVar(&opts.repo, "repo", ".", "path to the local source repository")
	cmd.Flags().BoolVar(&opts.noNetwork, "no-network", false, "disable network access when supported by the runtime")
	cmd.Flags().BoolVar(&inspectOpts.json, "json", false, "print local store metadata as JSON")
	cmd.Flags().StringVar(&inspectOpts.format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&inspectOpts.files, "files", false, "include the verified stored file inventory")

	return cmd
}
