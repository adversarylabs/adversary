package cmd

import (
	"fmt"
	"strings"

	"github.com/adversarylabs/adversary/internal/application"
	internalpaths "github.com/adversarylabs/adversary/internal/paths"
	traininbox "github.com/adversarylabs/adversary/internal/train/inbox"
	"github.com/spf13/cobra"
)

func renderTrainingInboxNotice(command *cobra.Command, deps application.Dependencies) {
	if deps.TTY == nil || !deps.TTY.Interactive(command.InOrStdin()) {
		return
	}
	path := command.CommandPath()
	if strings.Contains(path, " completion") || strings.HasSuffix(path, " help") {
		return
	}
	if flag := command.Flag("json"); flag != nil && flag.Changed {
		return
	}
	if flag := command.Flag("format"); flag != nil && flag.Changed && strings.EqualFold(flag.Value.String(), "json") {
		return
	}
	if flag := command.Flag("quiet"); flag != nil && flag.Changed {
		return
	}
	dataRoot, err := internalpaths.DataDir()
	if err != nil {
		return
	}
	if notice := trainingInboxNotice(dataRoot); notice != "" {
		fmt.Fprintln(command.ErrOrStderr(), notice)
	}
}

func trainingInboxNotice(dataRoot string) string {
	catalogs, err := traininbox.Pending(dataRoot)
	if err != nil || len(catalogs) == 0 {
		return ""
	}
	total := 0
	for _, catalog := range catalogs {
		total += catalog.Pending
	}
	return fmt.Sprintf("Training inbox: %d result(s) ready across %d catalog(s). Run: adversary catalog train review", total, len(catalogs))
}
