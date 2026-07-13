package cmd

import (
	"fmt"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"io"
	"strings"
)

func whoamiData(account adversarylabs.WhoamiResponse) whoamiDTO {
	name := account.Name
	email := account.EmailAddress
	if email == "" {
		email = account.Email
	}
	subscription := account.Subscription.Name
	if subscription == "" {
		subscription = account.Subscription.Plan
	}
	return whoamiDTO{true, name, email, subscription, account.Subscription.Status}
}

func printWhoami(stdout io.Writer, account adversarylabs.WhoamiResponse) {
	name := account.Name
	if name == "" {
		name = "(none)"
	}
	email := account.EmailAddress
	if email == "" {
		email = account.Email
	}
	if email == "" {
		email = "(none)"
	}
	subscription := account.Subscription.Name
	if subscription == "" {
		subscription = account.Subscription.Plan
	}
	if subscription == "" {
		subscription = "(none)"
	}
	status := account.Subscription.Status
	if status == "" {
		status = "(unknown)"
	}
	fmt.Fprintln(stdout, "Logged in to Adversary Labs.")
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "Name: %s\n", name)
	fmt.Fprintf(stdout, "Email: %s\n", email)
	fmt.Fprintf(stdout, "Subscription: %s\n", subscription)
	fmt.Fprintf(stdout, "Status: %s\n", status)
}

func shortDigest(digest string) string {
	if len(digest) <= 19 {
		return digest
	}
	if strings.HasPrefix(digest, "sha256:") {
		return digest[:19]
	}
	return digest[:12]
}

func humanSize(size int64) string {
	units := []string{"B", "KB", "MB", "GB"}
	value := float64(size)
	unit := units[0]
	for i := 1; i < len(units) && value >= 1024; i++ {
		value /= 1024
		unit = units[i]
	}
	if unit == "B" {
		return fmt.Sprintf("%d B", size)
	}
	return fmt.Sprintf("%.1f %s", value, unit)
}

func valueOf(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
