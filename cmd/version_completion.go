package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

func newVersionCommand() *cobra.Command {
	var format string
	var legacyJSON bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the adversary version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := commandFormat(cmd, format, legacyJSON)
			if err != nil {
				return err
			}
			if legacyJSON {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning: --json is deprecated; use --format json.")
			}
			v := currentVersion()
			if resolved == "json" {
				return writeJSON(cmd.OutOrStdout(), "version", v)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "adversary %s\n", v.Version)
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&legacyJSON, "json", false, "deprecated alias for --format json")
	return cmd
}

func newCompletionCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{Use: "completion [bash|zsh|fish|powershell]", Short: "Generate shell completion code", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return root.GenBashCompletion(cmd.OutOrStdout())
		case "zsh":
			return root.GenZshCompletion(cmd.OutOrStdout())
		case "fish":
			return root.GenFishCompletion(cmd.OutOrStdout(), true)
		case "powershell":
			return root.GenPowerShellCompletion(cmd.OutOrStdout())
		default:
			return fmt.Errorf("unsupported shell %q (want bash, zsh, fish, or powershell)", args[0])
		}
	}}
}
