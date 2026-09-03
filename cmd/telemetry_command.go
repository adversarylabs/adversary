package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/spf13/cobra"
)

var traceIDRE = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

func newTelemetryCommand(app *application.App, apiURL, profile *string) *cobra.Command {
	root := &cobra.Command{Use: "telemetry", Short: "Inspect privacy-safe run telemetry", Args: cobra.NoArgs}
	var outputFile string
	pull := &cobra.Command{
		Use: "pull <trace-id>", Short: "Download a run trace as OpenTelemetry JSON", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			traceID := strings.ToLower(strings.TrimSpace(args[0]))
			if !traceIDRE.MatchString(traceID) {
				return fmt.Errorf("trace id must be 32 hexadecimal characters")
			}
			deps := app.Dependencies()
			auth, ok, err := scopedAuth(deps.Auth, valueOf(apiURL), valueOf(profile), deps.RegistryHost)
			if err != nil {
				return err
			}
			if !ok || auth.Token == "" {
				return fmt.Errorf("telemetry pull requires adversary login")
			}
			raw, err := deps.API.New(valueOf(apiURL)).PullTelemetry(cmd.Context(), auth.Token, traceID)
			if err != nil {
				return err
			}
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, raw, "", "  "); err != nil {
				return err
			}
			pretty.WriteByte('\n')
			if outputFile == "" {
				_, err = cmd.OutOrStdout().Write(pretty.Bytes())
				return err
			}
			file, err := openTelemetryOutput(outputFile)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = file.Write(pretty.Bytes())
			return err
		},
	}
	pull.Flags().StringVar(&outputFile, "output-file", "", "write the OTLP JSON trace to this file")
	root.AddCommand(pull)
	return root
}
