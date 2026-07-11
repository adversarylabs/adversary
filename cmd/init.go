package cmd

import (
	"github.com/adversarylabs/adversary/internal/initproject"
	"github.com/spf13/cobra"
)

type initOptions struct{ sdk string }

func newInitCommand() *cobra.Command {
	opts := &initOptions{}

	cmd := &cobra.Command{
		Use:   "init <name>",
		Short: "Create a new adversary project",
		Example: `  adversary init my-adversary
  adversary init my-adversary --sdk typescript`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := initproject.Create(initproject.Options{
				Destination: args[0],
				SDK:         opts.sdk,
			})
			if err != nil {
				return err
			}
			initproject.RenderSuccess(cmd.OutOrStdout(), result, args[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.sdk, "sdk", initproject.DefaultSDK, "SDK template to use: typescript")

	return cmd
}
