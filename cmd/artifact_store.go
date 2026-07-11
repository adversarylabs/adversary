package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/spf13/cobra"
)

func newStoreCommand(app *application.App) *cobra.Command {
	deps := app.Dependencies()
	root := &cobra.Command{Use: "store", Short: "Inspect and maintain the artifact repository"}
	checkJSON := false
	check := &cobra.Command{Use: "check", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		report, err := deps.Repository.CheckAll()
		if err != nil {
			return &application.Error{Operation: "store check", Kind: "repository", Err: err}
		}
		if checkJSON {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(report)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Healthy: %t\nRecords: %d\nReferences: %d\n", report.Healthy, len(report.Records), len(report.References))
		if !report.Healthy {
			return &application.Error{Operation: "store check", Kind: "corrupt", Err: fmt.Errorf("repository check failed")}
		}
		return nil
	}}
	check.Flags().BoolVar(&checkJSON, "json", false, "emit JSON")
	dry, apply, yes, gcJSON := false, false, false, false
	gc := &cobra.Command{Use: "gc", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		plan, err := deps.Repository.PlanGC()
		if err != nil {
			return &application.Error{Operation: "store gc plan", Kind: "repository", Err: err}
		}
		if apply && !yes {
			return &application.Error{Operation: "store gc apply", Kind: "confirmation", Err: fmt.Errorf("--apply requires --yes")}
		}
		if !apply {
			dry = true
		}
		report, err := deps.Repository.ApplyGC(plan, dry)
		if err != nil {
			return &application.Error{Operation: "store gc apply", Kind: "repository", Resource: plan.ID, Err: err}
		}
		if gcJSON {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(report)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Plan: %s\nDry run: %t\nPlanned records: %d\nDeleted records: %d\n", report.PlanID, report.DryRun, len(report.PlannedRecords), len(report.DeletedRecords))
		return nil
	}}
	gc.Flags().BoolVar(&dry, "dry-run", false, "plan without deletion")
	gc.Flags().BoolVar(&apply, "apply", false, "apply the current plan")
	gc.Flags().BoolVar(&yes, "yes", false, "confirm deletion")
	gc.Flags().BoolVar(&gcJSON, "json", false, "emit JSON")
	refYes := false
	refDelete := &cobra.Command{Use: "ref-delete <reference> <expected-digest>", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		if !refYes {
			return &application.Error{Operation: "store ref-delete", Kind: "confirmation", Resource: args[0], Err: fmt.Errorf("ref-delete requires --yes")}
		}
		if err := deps.Repository.DeleteRef(args[0], args[1]); err != nil {
			return &application.Error{Operation: "store ref-delete", Kind: "repository", Resource: args[0], Err: err}
		}
		return nil
	}}
	refDelete.Flags().BoolVar(&refYes, "yes", false, "confirm reference deletion")
	statusJSON := false
	status := &cobra.Command{Use: "migration-status <name>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		got, err := deps.Repository.MigrationStatus(args[0])
		if err != nil {
			return &application.Error{Operation: "store migration-status", Kind: "repository", Resource: args[0], Err: err}
		}
		if statusJSON {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(got)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Migration: %s\nImported: %d\nRemaining: %d\nComplete: %t\n", got.Name, got.Checkpoint.Imported, got.Remaining, got.Complete)
		return nil
	}}
	status.Flags().BoolVar(&statusJSON, "json", false, "emit JSON")
	root.AddCommand(check, gc, refDelete, status)
	return root
}
