package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/initproject"
	"github.com/adversarylabs/adversary/internal/version"
	adversarypkg "github.com/adversarylabs/adversary/pkg/adversary"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/adversarylabs/adversary/pkg/store"
	"github.com/spf13/cobra"
)

func Execute() error {
	root := NewRootCommand(os.Stdout, os.Stderr)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}

func NewRootCommand(stdout, stderr io.Writer) *cobra.Command {
	var apiURL string
	cmd := &cobra.Command{
		Use:           "adversary",
		Short:         "Run source-code adversaries against a local repository",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.PersistentFlags().StringVar(&apiURL, "api-url", adversarylabs.ResolveAPIURL(""), "Adversary Labs API endpoint (or ADVERSARY_API_URL)")

	cmd.AddCommand(newRunCommand(stdout, stderr))
	cmd.AddCommand(newInspectCommand(stdout, stderr))
	cmd.AddCommand(newInitCommand(stdout, stderr))
	cmd.AddCommand(newPackCommand(stdout, stderr))
	cmd.AddCommand(newLSCommand(stdout, "ls"))
	cmd.AddCommand(newLSCommand(stdout, "list"))
	cmd.AddCommand(newVersionCommand(stdout))
	cmd.AddCommand(newLoginCommand(stdout, stderr, &apiURL))
	cmd.AddCommand(newLogoutCommand(stdout, stderr, &apiURL))
	cmd.AddCommand(newPushCommand(stdout, stderr, &apiURL))
	cmd.AddCommand(newPullCommand(stdout, stderr, &apiURL))
	cmd.AddCommand(newSearchCommand(stdout, stderr, &apiURL))
	cmd.AddCommand(newWhoamiCommand(stdout, stderr, &apiURL))
	return cmd
}

type runOptions struct {
	repo      string
	base      string
	head      string
	force     bool
	format    string
	keepTemp  bool
	noNetwork bool
	verbose   bool
	shell     bool
	allFiles  bool
}

type initOptions struct {
	sdk string
}

type loginOptions struct {
	ci           bool
	name         string
	emailAddress string
	password     string
}

type logoutOptions struct {
	localOnly bool
}

type inspectOptions struct {
	json bool
}

type listOptions struct {
	json bool
}

type packOptions struct {
	builder string
	name    string
}

func newRunCommand(stdout, stderr io.Writer) *cobra.Command {
	opts := &runOptions{}

	cmd := &cobra.Command{
		Use:   "run <adversary-ref>",
		Short: "Run an Adversary against a local source repository",
		Example: `  adversary run ./smoke-tests/comment-sentence-adversary --repo .
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --verbose
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --format json
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --base main --head HEAD
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --base main --head HEAD --all-files
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --shell`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.format != "text" && opts.format != "json" {
				return fmt.Errorf("--format must be text or json")
			}

			runner := internaladversary.Runner{
				Stdout: stdout,
				Stderr: stderr,
			}

			err := runner.Run(cmd.Context(), internaladversary.RunOptions{
				AdversaryRef: args[0],
				RepoPath:     opts.repo,
				BaseRef:      opts.base,
				HeadRef:      opts.head,
				Force:        opts.force,
				Format:       opts.format,
				KeepTemp:     opts.keepTemp,
				NoNetwork:    opts.noNetwork,
				Verbose:      opts.verbose,
				Shell:        opts.shell,
				AllFiles:     opts.allFiles,
			})
			if errors.Is(err, context.Canceled) {
				return err
			}
			return err
		},
	}

	cmd.Flags().StringVar(&opts.repo, "repo", ".", "path to the local source repository")
	cmd.Flags().StringVar(&opts.base, "base", "", "git base ref for change context")
	cmd.Flags().StringVar(&opts.head, "head", "", "git head ref for change context")
	cmd.Flags().BoolVar(&opts.force, "force", false, "run even when triggers.files_changed does not match")
	cmd.Flags().StringVar(&opts.format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&opts.keepTemp, "keep-temp", false, "do not delete the temporary run directory")
	cmd.Flags().BoolVar(&opts.noNetwork, "no-network", false, "disable network access when supported by the runtime")
	cmd.Flags().BoolVar(&opts.verbose, "verbose", false, "print detailed execution diagnostics")
	cmd.Flags().BoolVar(&opts.shell, "shell", false, "launch an interactive shell in the adversary working directory")
	cmd.Flags().BoolVar(&opts.allFiles, "all-files", false, "scan all files even when diff refs are provided")

	return cmd
}

func newInspectCommand(stdout, stderr io.Writer) *cobra.Command {
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
			localStore, err := store.Default()
			if err == nil {
				if record, err := localStore.Inspect(args[0]); err == nil {
					return renderStoreInspect(stdout, record, inspectOpts.json)
				}
			}
			if inspectOpts.json {
				return fmt.Errorf("--json is only supported for locally stored adversaries")
			}
			runner := internaladversary.Runner{
				Stdout: stdout,
				Stderr: stderr,
			}
			return runner.Inspect(internaladversary.RunOptions{
				AdversaryRef: args[0],
				RepoPath:     opts.repo,
				NoNetwork:    opts.noNetwork,
			})
		},
	}

	cmd.Flags().StringVar(&opts.repo, "repo", ".", "path to the local source repository")
	cmd.Flags().BoolVar(&opts.noNetwork, "no-network", false, "disable network access when supported by the runtime")
	cmd.Flags().BoolVar(&inspectOpts.json, "json", false, "print local store metadata as JSON")

	return cmd
}

func newPackCommand(stdout, stderr io.Writer) *cobra.Command {
	opts := &packOptions{builder: "local"}
	cmd := &cobra.Command{
		Use:   "pack <path>",
		Short: "Package the current adversary into the local content-addressable store",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(stderr, "Packing adversary...")
			artifact, err := pack.Create(cmd.Context(), pack.Options{Dir: args[0], NameOverride: opts.name, Build: true, Builder: opts.builder, Stdout: stderr, Stderr: stderr})
			if err != nil {
				return err
			}
			localStore, err := store.Default()
			if err != nil {
				return err
			}
			record, err := localStore.Put(artifact)
			if err != nil {
				return err
			}
			fmt.Fprintln(stdout)
			fmt.Fprintf(stdout, "Name: %s\n", record.Name)
			fmt.Fprintf(stdout, "Version: %s\n", record.Version)
			fmt.Fprintf(stdout, "Runtime: %s\n", record.Runtime)
			if record.RuntimeName != "" {
				fmt.Fprintf(stdout, "Runtime Requirement: %s@%s\n", record.RuntimeName, record.RuntimeVersion)
			}
			fmt.Fprintf(stdout, "Digest: %s\n", record.Digest)
			fmt.Fprintf(stdout, "Size: %s\n", humanSize(record.Size))
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "Stored locally as:")
			fmt.Fprintln(stdout)
			fmt.Fprintf(stdout, "%s:%s\n", record.Name, record.Version)
			fmt.Fprintf(stdout, "%s:latest\n", record.Name)
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.builder, "builder", "local", "build mechanism: local or docker")
	cmd.Flags().StringVar(&opts.name, "name", "", "override the local artifact name")
	return cmd
}

func newLSCommand(stdout io.Writer, use string) *cobra.Command {
	opts := &listOptions{}
	cmd := &cobra.Command{
		Use:   use,
		Short: "List locally stored adversaries",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			localStore, err := store.Default()
			if err != nil {
				return err
			}
			records, err := localStore.List()
			if err != nil {
				return err
			}
			if opts.json {
				encoder := json.NewEncoder(stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(records)
			}
			if len(records) == 0 {
				fmt.Fprintln(stdout, "No local adversaries found.")
				return nil
			}
			w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tVERSION\tDIGEST\tSIZE\tCREATED")
			for _, record := range records {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", record.Name, record.Version, shortDigest(record.Digest), humanSize(record.Size), relativeTime(record.Created))
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&opts.json, "json", false, "print local adversaries as JSON")
	return cmd
}

func newInitCommand(stdout, stderr io.Writer) *cobra.Command {
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
			initproject.RenderSuccess(stdout, result, args[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.sdk, "sdk", initproject.DefaultSDK, "SDK template to use: typescript")

	return cmd
}

func newVersionCommand(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the adversary version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(stdout, "adversary %s\n", version.Version)
			return nil
		},
	}
}

func newLoginCommand(stdout, stderr io.Writer, apiURL *string) *cobra.Command {
	opts := &loginOptions{}
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with Adversary Labs",
		Example: `  adversary login
  adversary login --name "Marc's MacBook Pro"
  adversary login --ci
  adversary login --email-address marc@example.com
  adversary login --email-address marc@example.com --password "$ADVERSARY_PASSWORD"`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := adversarylabs.DefaultConfigStore()
			if err != nil {
				return err
			}
			client := adversarylabs.NewClientWithBaseURL(store, valueOf(apiURL))
			var token adversarylabs.TokenResponse
			if opts.emailAddress != "" || opts.password != "" {
				if opts.emailAddress == "" {
					return fmt.Errorf("--email-address is required when --password is provided")
				}
				password := opts.password
				if password == "" {
					var err error
					password, err = promptPassword(stderr)
					if err != nil {
						return err
					}
				}
				token, err = client.LoginWithPassword(cmd.Context(), adversarylabs.PasswordLoginOptions{
					EmailAddress: opts.emailAddress,
					Password:     password,
					Name:         opts.name,
					CI:           opts.ci,
				})
				if err != nil {
					return err
				}
			} else {
				token, err = loginWithBrowser(cmd.Context(), stdout, client, opts)
				if err != nil {
					return err
				}
			}
			if err := store.SetAuth(adversarylabs.ResolveRegistryHost(), adversarylabs.Auth{
				Token:             token.Token,
				ClientID:          token.ClientID,
				ExpiresAt:         token.ExpiresAt,
				RegistryNamespace: token.RegistryNamespace,
				Namespace:         token.Namespace,
				Team:              token.Team,
			}); err != nil {
				return err
			}
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "Logged in to Adversary Labs.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&opts.ci, "ci", false, "request a short-lived automation token")
	cmd.Flags().StringVar(&opts.name, "name", "", "friendly name for this client")
	cmd.Flags().StringVar(&opts.emailAddress, "email-address", "", "email address for password login")
	cmd.Flags().StringVar(&opts.password, "password", "", "password for password login; if omitted with --email-address, prompt securely")
	return cmd
}

func newLogoutCommand(stdout, stderr io.Writer, apiURL *string) *cobra.Command {
	opts := &logoutOptions{}
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Log out of Adversary Labs",
		Example: `  adversary logout
  adversary logout --local-only`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := adversarylabs.DefaultConfigStore()
			if err != nil {
				return err
			}
			auth, ok, err := store.RemoveAuth(adversarylabs.ResolveRegistryHost())
			if err != nil {
				return err
			}
			if !ok {
				fmt.Fprintln(stdout, "No Adversary Labs login was configured.")
				return nil
			}
			if !opts.localOnly && auth.Token != "" {
				client := adversarylabs.NewClientWithBaseURL(store, valueOf(apiURL))
				if err := client.Revoke(cmd.Context(), auth.Token); err != nil {
					fmt.Fprintf(stderr, "Token revocation failed: %v\n", err)
					fmt.Fprintln(stdout, "Removed local Adversary Labs credentials.")
					return nil
				}
			}
			fmt.Fprintln(stdout, "Logged out of Adversary Labs.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&opts.localOnly, "local-only", false, "remove local credentials without contacting Adversary Labs")
	return cmd
}

func newPushCommand(stdout, stderr io.Writer, apiURL *string) *cobra.Command {
	return &cobra.Command{
		Use:   "push <local-ref> [remote-ref]",
		Short: "Push a locally packed adversary to an OCI registry",
		Example: `  adversary push dockerfile-reviewer:0.1.0
  adversary push security-reviewer:0.1.0 ghcr.io/acme/security-reviewer:0.1.0
  adversary push sha256:abc123 ghcr.io/acme/security-reviewer:0.1.0
  adversary push ghcr.io/acme/security-reviewer:0.1.0`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			localRef := args[0]
			remoteRef := ""
			if len(args) == 2 {
				remoteRef = args[1]
			} else {
				remoteRef = localRef
			}
			localStore, err := store.Default()
			if err != nil {
				return err
			}
			record, err := localStore.Inspect(localRef)
			if err != nil {
				return err
			}
			adversaryManifest, err := localStore.AdversaryManifest(record)
			if err != nil {
				return err
			}
			if len(args) == 1 && !hasExplicitRegistry(localRef) {
				remoteRef, err = defaultAdversaryLabsPushRef(cmd.Context(), localRef, record, valueOf(apiURL))
				if err != nil {
					return err
				}
			}
			ref, err := oci.ParseReference(remoteRef)
			if err != nil {
				return err
			}
			manifest, blobs, err := localStore.OCIPayload(record)
			if err != nil {
				return err
			}
			registry := newOCIRegistry(valueOf(apiURL))
			if ref.Registry == "localhost" || hasLocalhostPort(ref.Registry) {
				registry.PlainHTTP = true
			}
			fmt.Fprintln(stderr, "Pushing adversary...")
			fmt.Fprintf(stderr, "Local:  %s\n", localRef)
			fmt.Fprintf(stderr, "Remote: %s\n", ref.Locator())
			fmt.Fprintln(stderr, "Pushing layers...")
			fmt.Fprintln(stderr, "Pushing manifest...")
			digest, err := registry.Push(cmd.Context(), ref, manifest, blobs)
			if err != nil {
				return pushErrorWithNamespaceHint(err, localRef, ref)
			}
			artifactDigest, _, err := registry.PushAdversaryManifestReferrer(cmd.Context(), ref, digest, adversaryManifest)
			if err != nil {
				return fmt.Errorf("image pushed, but adversary.yaml referrer publish failed for %s with image digest %s: %w", ref.Locator(), digest, err)
			}
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "Pushed image")
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, ref.Locator())
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "Image digest")
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, digest)
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "Published adversary manifest referrer")
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, artifactDigest)
			return nil
		},
	}
}

func newPullCommand(stdout, stderr io.Writer, apiURL *string) *cobra.Command {
	return &cobra.Command{
		Use:   "pull <reference>",
		Short: "Pull and install an adversary from an OCI registry",
		Example: `  adversary pull security-reviewer
  adversary pull adversarylabs/security-reviewer
  adversary pull ghcr.io/acme/security-reviewer
  adversary pull localhost:5000/security-reviewer`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref, err := oci.ParseReference(args[0])
			if err != nil {
				return err
			}
			registry := newOCIRegistry(valueOf(apiURL))
			if ref.Registry == "localhost" || hasLocalhostPort(ref.Registry) {
				registry.PlainHTTP = true
			}
			fmt.Fprintln(stderr, "Pulling manifest...")
			fmt.Fprintln(stderr)
			cache, err := adversarypkg.DefaultCache()
			if err != nil {
				return err
			}
			digest, err := registry.Resolve(cmd.Context(), ref)
			if err != nil {
				return err
			}
			if record, ok := cache.ResolveDigest(digest); ok {
				printInstallRecord(stdout, record)
				return nil
			}
			fmt.Fprintln(stderr, "Downloading layers...")
			artifact, err := registry.Pull(cmd.Context(), ref)
			if err != nil {
				return err
			}
			record, err := cache.Install(artifact)
			if err != nil {
				return err
			}
			printInstallRecord(stdout, record)
			return nil
		},
	}
}

func newSearchCommand(stdout, stderr io.Writer, apiURL *string) *cobra.Command {
	return &cobra.Command{
		Use:   "search <query>",
		Short: "Search Adversary Labs adversaries",
		Example: `  adversary search dockerfile
  adversary search security-reviewer`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := adversarylabs.DefaultConfigStore()
			if err != nil {
				return err
			}
			var token string
			if auth, ok := store.Auth(adversarylabs.ResolveRegistryHost()); ok {
				token = auth.Token
			}
			client := adversarylabs.NewClientWithBaseURL(store, valueOf(apiURL))
			results, err := client.Search(cmd.Context(), args[0], token)
			if err != nil {
				return err
			}
			if len(results) == 0 {
				fmt.Fprintln(stdout, "No adversaries found.")
				return nil
			}
			for _, result := range results {
				name := result.Name
				if result.Reference != "" {
					name = result.Reference
				}
				if result.Version != "" {
					fmt.Fprintf(stdout, "%s\t%s", name, result.Version)
				} else {
					fmt.Fprint(stdout, name)
				}
				if result.Description != "" {
					fmt.Fprintf(stdout, "\t%s", result.Description)
				}
				fmt.Fprintln(stdout)
			}
			return nil
		},
	}
}

func newWhoamiCommand(stdout, stderr io.Writer, apiURL *string) *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the current Adversary Labs login",
		Example: `  adversary whoami
  adversary whoami --api-url http://localhost:3000/api`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := adversarylabs.DefaultConfigStore()
			if err != nil {
				return err
			}
			auth, ok := store.Auth(adversarylabs.ResolveRegistryHost())
			if !ok {
				fmt.Fprintln(stdout, "Not logged in.")
				fmt.Fprintln(stdout)
				fmt.Fprintln(stdout, "Run `adversary login` to authenticate with Adversary Labs.")
				return nil
			}
			client := adversarylabs.NewClientWithBaseURL(store, valueOf(apiURL))
			account, err := client.Whoami(cmd.Context(), auth.Token)
			if err != nil {
				return err
			}
			printWhoami(stdout, account)
			return nil
		},
	}
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

func renderStoreInspect(stdout io.Writer, record store.Record, asJSON bool) error {
	if asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(record)
	}
	fmt.Fprintf(stdout, "Name: %s\n", record.Name)
	fmt.Fprintf(stdout, "Version: %s\n", record.Version)
	fmt.Fprintf(stdout, "Digest: %s\n", record.Digest)
	fmt.Fprintf(stdout, "Runtime: %s\n", record.Runtime)
	if record.RuntimeName != "" {
		fmt.Fprintf(stdout, "Runtime Requirement: %s@%s\n", record.RuntimeName, record.RuntimeVersion)
	}
	fmt.Fprintf(stdout, "Entrypoint: %s\n", strings.Join(record.Entrypoint, " "))
	permissions, _ := json.Marshal(record.Permissions)
	if len(permissions) == 0 || string(permissions) == "null" {
		permissions = []byte("{}")
	}
	fmt.Fprintf(stdout, "Permissions: %s\n", permissions)
	fmt.Fprintf(stdout, "Size: %s\n", humanSize(record.Size))
	fmt.Fprintf(stdout, "Created: %s\n", record.Created.Format(time.RFC3339))
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Layers:")
	fmt.Fprintf(stdout, "  config  %s\n", record.ConfigDigest)
	fmt.Fprintf(stdout, "  layer   %s\n", record.LayerDigest)
	if len(record.Annotations) > 0 {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Manifest annotations:")
		keys := make([]string, 0, len(record.Annotations))
		for key := range record.Annotations {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(stdout, "  %s: %s\n", key, record.Annotations[key])
		}
	}
	if len(record.Files) > 0 {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Files:")
		for _, file := range record.Files {
			fmt.Fprintf(stdout, "  %s  %s\n", file.Path, humanSize(file.Size))
		}
	}
	return nil
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

func relativeTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	d := time.Since(t)
	if d < time.Minute {
		return "now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func valueOf(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func waitForLogin(ctx context.Context, client adversarylabs.Client, login adversarylabs.DeviceLogin) (adversarylabs.TokenResponse, error) {
	interval := adversarylabs.PollInterval(login)
	deadline := time.Now().Add(time.Duration(login.ExpiresIn) * time.Second)
	if login.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}
	for {
		token, err := client.PollToken(ctx, login.DeviceCode)
		if err == nil {
			return token, nil
		}
		if time.Now().After(deadline) {
			return adversarylabs.TokenResponse{}, fmt.Errorf("login expired before authentication completed")
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return adversarylabs.TokenResponse{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func loginWithBrowser(ctx context.Context, stdout io.Writer, client adversarylabs.Client, opts *loginOptions) (adversarylabs.TokenResponse, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("start local login callback: %w", err)
	}
	defer listener.Close()

	result := make(chan adversarylabs.TokenResponse, 1)
	failures := make(chan error, 1)
	server := &http.Server{}
	mux := http.NewServeMux()
	server.Handler = mux
	callbackURL := "http://" + listener.Addr().String() + "/callback"
	mux.HandleFunc("/callback", func(w http.ResponseWriter, req *http.Request) {
		query := req.URL.Query()
		if message := query.Get("error"); message != "" {
			failures <- fmt.Errorf("login failed: %s", message)
			http.Error(w, "Login failed. You can close this window.", http.StatusBadRequest)
			return
		}
		if token := query.Get("token"); token != "" {
			result <- adversarylabs.TokenResponse{
				Token:     token,
				ClientID:  query.Get("client_id"),
				ExpiresAt: query.Get("expires_at"),
			}
			fmt.Fprintln(w, "Login complete. You can close this window.")
			return
		}
		if code := query.Get("code"); code != "" {
			token, err := client.ExchangeCode(req.Context(), code)
			if err != nil {
				failures <- err
				http.Error(w, "Login failed. You can close this window.", http.StatusBadGateway)
				return
			}
			result <- token
			fmt.Fprintln(w, "Login complete. You can close this window.")
			return
		}
		failures <- fmt.Errorf("login callback did not include a token or code")
		http.Error(w, "Login callback was missing credentials.", http.StatusBadRequest)
	})
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			failures <- err
		}
	}()
	defer server.Close()

	loginURL, err := client.BrowserLoginURL(adversarylabs.BrowserLoginOptions{
		RedirectURI: callbackURL,
		Name:        opts.name,
		CI:          opts.ci,
	})
	if err != nil {
		return adversarylabs.TokenResponse{}, err
	}
	fmt.Fprintln(stdout, "Opening browser for Adversary Labs login...")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, loginURL)
	fmt.Fprintln(stdout)
	if err := openBrowser(loginURL); err != nil {
		fmt.Fprintf(stdout, "Could not open browser automatically: %v\n", err)
		fmt.Fprintln(stdout, "Open the URL above to continue.")
		fmt.Fprintln(stdout)
	}
	fmt.Fprintln(stdout, "Waiting for browser authentication...")
	select {
	case token := <-result:
		return token, nil
	case err := <-failures:
		return adversarylabs.TokenResponse{}, err
	case <-ctx.Done():
		return adversarylabs.TokenResponse{}, ctx.Err()
	}
}

func promptPassword(stderr io.Writer) (string, error) {
	fmt.Fprint(stderr, "Password: ")
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("--password is required when no interactive terminal is available")
	}
	defer tty.Close()
	disableEcho := exec.Command("stty", "-echo")
	disableEcho.Stdin = tty
	_ = disableEcho.Run()
	defer func() {
		enableEcho := exec.Command("stty", "echo")
		enableEcho.Stdin = tty
		_ = enableEcho.Run()
	}()
	password, err := bufio.NewReader(tty).ReadString('\n')
	fmt.Fprintln(stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(password, "\r\n"), nil
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

func newOCIRegistry(apiURL string) *oci.HTTPRegistry {
	registry := oci.NewHTTPRegistry()
	if strings.TrimSpace(os.Getenv("ADVERSARY_OCI_DEBUG")) != "" {
		registry.Debug = os.Stderr
	}
	registry.BearerRealm = registryAuthRealm(apiURL)
	registry.BearerService = adversarylabs.ResolveRegistryHost()
	store, err := adversarylabs.DefaultConfigStore()
	if err == nil {
		registry.Credentials = oci.ChainCredentialStore{store, oci.DockerCredentialStore{}}
	}
	return registry
}

func registryAuthRealm(apiURL string) string {
	base := strings.TrimRight(adversarylabs.ResolveAPIURL(apiURL), "/")
	base = strings.TrimSuffix(base, "/api")
	return base + "/auth/registry"
}

func printInstallRecord(stdout io.Writer, record adversarypkg.InstallRecord) {
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Installed:")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, record.Name)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Version:")
	fmt.Fprintln(stdout)
	if record.Version == "" {
		fmt.Fprintln(stdout, "(none)")
	} else {
		fmt.Fprintln(stdout, record.Version)
	}
}

func hasLocalhostPort(registry string) bool {
	return registry == "127.0.0.1" || registry == "[::1]" ||
		len(registry) > len("localhost:") && registry[:len("localhost:")] == "localhost:" ||
		len(registry) > len("127.0.0.1:") && registry[:len("127.0.0.1:")] == "127.0.0.1:"
}

func hasExplicitRegistry(ref string) bool {
	name := ref
	if before, _, ok := strings.Cut(name, "@"); ok {
		name = before
	}
	lastSlash := strings.LastIndex(name, "/")
	lastColon := strings.LastIndex(name, ":")
	if lastColon > lastSlash {
		name = name[:lastColon]
	}
	first, _, ok := strings.Cut(name, "/")
	if !ok {
		return false
	}
	return strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost"
}

func defaultAdversaryLabsPushRef(ctx context.Context, localRef string, record store.Record, apiURL string) (string, error) {
	configStore, err := adversarylabs.DefaultConfigStore()
	if err != nil {
		return "", err
	}
	registryHost := adversarylabs.ResolveRegistryHost()
	auth, ok := configStore.Auth(registryHost)
	if !ok {
		if registryHost != adversarylabs.DefaultRegistry {
			namespace := cleanRegistryNamespace(os.Getenv("ADVERSARY_REGISTRY_NAMESPACE"))
			if namespace == "" {
				namespace = oci.DefaultNamespace
			}
			return defaultRegistryPushRef(registryHost, namespace, record), nil
		}
		return "", fmt.Errorf("remote reference is required for unqualified local ref %q; run adversary login or provide a remote reference", localRef)
	}
	namespace := registryNamespaceFromAuth(auth)
	if namespace == "" {
		client := adversarylabs.NewClientWithBaseURL(configStore, apiURL)
		account, err := client.Whoami(ctx, auth.Token)
		if err != nil {
			if registryHost != adversarylabs.DefaultRegistry {
				namespace = oci.DefaultNamespace
			} else {
				return "", err
			}
		} else {
			namespace = registryNamespaceFromAccount(account)
		}
	}
	namespace = cleanRegistryNamespace(namespace)
	if namespace == "" {
		if registryHost != adversarylabs.DefaultRegistry {
			namespace = oci.DefaultNamespace
		}
	}
	if namespace == "" {
		return "", fmt.Errorf("logged in, but Adversary Labs did not provide a registry namespace; provide a remote reference explicitly")
	}
	return defaultRegistryPushRef(registryHost, namespace, record), nil
}

func defaultRegistryPushRef(registryHost, namespace string, record store.Record) string {
	name := manifestNameForRemote(record.Name)
	tag := record.Version
	if tag == "" {
		tag = oci.DefaultTag
	}
	return registryHost + "/" + namespace + "/" + name + ":" + tag
}

func pushErrorWithNamespaceHint(err error, localRef string, ref oci.Reference) error {
	if err == nil || !isRegistryAccessDenied(err) {
		return err
	}
	namespace := registryNamespaceFromReference(ref)
	if namespace == "" {
		return err
	}
	suggested := ref.Registry + "/<slug>/" + ref.ShortName()
	if ref.Digest != "" {
		suggested += "@" + ref.Digest
	} else {
		suggested += ":" + ref.Tag
	}
	return fmt.Errorf("push is not authorized for %s\n\nThe remote namespace %q may not match your Adversary Labs team slug. Push to your slug namespace, for example:\n  adversary push %s %s\n\nFor unqualified pushes, set ADVERSARY_REGISTRY_NAMESPACE=<slug>.\n\nOriginal error: %w", ref.Locator(), namespace, localRef, suggested, err)
}

func isRegistryAccessDenied(err error) bool {
	text := err.Error()
	return strings.Contains(text, "token request failed: 403 Forbidden") ||
		strings.Contains(text, `"code":"DENIED"`) ||
		strings.Contains(text, "Requested registry access is not authorized")
}

func registryNamespaceFromReference(ref oci.Reference) string {
	namespace, _, ok := strings.Cut(ref.Repository, "/")
	if !ok {
		return ""
	}
	return namespace
}

func registryNamespaceFromAuth(auth adversarylabs.Auth) string {
	for _, value := range []string{
		os.Getenv("ADVERSARY_REGISTRY_NAMESPACE"),
		auth.RegistryNamespace,
		auth.Namespace,
		auth.Team,
	} {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func registryNamespaceFromAccount(account adversarylabs.WhoamiResponse) string {
	for _, value := range []string{
		account.RegistryNamespace,
		account.Namespace,
		account.Team.Slug,
		account.Team.Name,
		account.Organization.Slug,
		account.Organization.Name,
	} {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	for _, team := range account.Teams {
		if strings.TrimSpace(team.Slug) != "" {
			return team.Slug
		}
		if strings.TrimSpace(team.Name) != "" {
			return team.Name
		}
	}
	return ""
}

func manifestNameForRemote(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "adversary"
	}
	parts := strings.Split(name, "/")
	last := strings.TrimSpace(parts[len(parts)-1])
	if last == "" {
		return "adversary"
	}
	return last
}

func cleanRegistryNamespace(namespace string) string {
	namespace = strings.TrimSpace(strings.ToLower(namespace))
	var b strings.Builder
	lastDash := false
	for _, r := range namespace {
		valid := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.'
		if valid {
			b.WriteRune(r)
			lastDash = r == '-'
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-.")
}
