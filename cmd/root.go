package cmd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	"sync"
	"text/tabwriter"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/initproject"
	"github.com/adversarylabs/adversary/internal/version"
	adversarypkg "github.com/adversarylabs/adversary/pkg/adversary"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/adversarylabs/adversary/pkg/repository"
	"github.com/adversarylabs/adversary/pkg/store"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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
	var profile string
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
	cmd.PersistentFlags().StringVar(&profile, "profile", "default", "credential profile")

	cmd.AddCommand(newRunCommand(stdout, stderr))
	cmd.AddCommand(newInspectCommand(stdout, stderr))
	cmd.AddCommand(newInitCommand(stdout, stderr))
	cmd.AddCommand(newPackCommand(stdout, stderr))
	cmd.AddCommand(newLSCommand(stdout, "ls"))
	cmd.AddCommand(newLSCommand(stdout, "list"))
	cmd.AddCommand(newVersionCommand(stdout))
	cmd.AddCommand(newLoginCommand(stdout, stderr, &apiURL, &profile))
	cmd.AddCommand(newLogoutCommand(stdout, stderr, &apiURL, &profile))
	cmd.AddCommand(newPushCommand(stdout, stderr, &apiURL, &profile))
	cmd.AddCommand(newPullCommand(stdout, stderr, &apiURL, &profile))
	cmd.AddCommand(newSearchCommand(stdout, stderr, &apiURL, &profile))
	cmd.AddCommand(newWhoamiCommand(stdout, stderr, &apiURL, &profile))
	return cmd
}

type runOptions struct {
	repo                     string
	base                     string
	head                     string
	builder                  string
	force                    bool
	format                   string
	json                     bool
	keepTemp                 bool
	noNetwork                bool
	verbose                  bool
	debug                    bool
	includeSuppressed        bool
	shell                    bool
	allFiles                 bool
	allowUnsafeHostExecution bool
}

type initOptions struct {
	sdk string
}

type loginOptions struct {
	ci            bool
	name          string
	emailAddress  string
	passwordStdin bool
	device        bool
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
			if opts.json {
				opts.format = "json"
			}
			if opts.debug {
				opts.verbose = true
			}
			if opts.shell && opts.noNetwork {
				return fmt.Errorf("--shell cannot be combined with --no-network because the host shell cannot enforce network isolation")
			}
			if opts.shell && (opts.json || opts.format == "json") {
				return fmt.Errorf("--shell cannot be combined with JSON output")
			}

			runner := internaladversary.Runner{
				Stdout: stdout,
				Stderr: stderr,
			}

			err := runner.Run(cmd.Context(), internaladversary.RunOptions{
				AdversaryRef:             args[0],
				RepoPath:                 opts.repo,
				BaseRef:                  opts.base,
				HeadRef:                  opts.head,
				Builder:                  opts.builder,
				Force:                    opts.force,
				Format:                   opts.format,
				KeepTemp:                 opts.keepTemp,
				NoNetwork:                opts.noNetwork,
				Verbose:                  opts.verbose,
				IncludeSuppressed:        opts.includeSuppressed,
				Shell:                    opts.shell,
				AllFiles:                 opts.allFiles,
				AllowUnsafeHostExecution: opts.allowUnsafeHostExecution,
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
	cmd.Flags().StringVar(&opts.builder, "builder", "local", "build mechanism for local adversaries: local or docker")
	cmd.Flags().BoolVar(&opts.force, "force", false, "run even when triggers.files_changed does not match")
	cmd.Flags().StringVar(&opts.format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&opts.json, "json", false, "print the versioned review result envelope as JSON")
	cmd.Flags().BoolVar(&opts.keepTemp, "keep-temp", false, "do not delete the temporary run directory")
	cmd.Flags().BoolVar(&opts.noNetwork, "no-network", false, "require network access to be disabled (fails if the executor cannot enforce it)")
	cmd.Flags().BoolVar(&opts.verbose, "verbose", false, "print detailed execution diagnostics")
	cmd.Flags().BoolVar(&opts.debug, "debug", false, "print detailed execution diagnostics")
	cmd.Flags().BoolVar(&opts.includeSuppressed, "include-suppressed", false, "request suppressed review findings when supported by the runtime")
	cmd.Flags().BoolVar(&opts.shell, "shell", false, "UNSAFE: launch an unrestricted host shell in the adversary working directory")
	cmd.Flags().BoolVar(&opts.allowUnsafeHostExecution, "allow-unsafe-host-execution", false, "acknowledge unrestricted host execution of installed or pulled code and --shell")
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
			resolver, err := internaladversary.DefaultResolver()
			if err != nil {
				return err
			}
			resolution, lookupErr := resolver.Lookup(args[0])
			if lookupErr == nil && !resolution.Local {
				if inspectOpts.json {
					return json.NewEncoder(stdout).Encode(struct {
						CanonicalReference string `json:"canonicalReference"`
						Digest             string `json:"digest"`
						Record             any    `json:"record"`
					}{resolution.CanonicalReference, resolution.Digest, resolution.Record})
				}
				fmt.Fprintf(stdout, "Canonical reference: %s\nDigest: %s\nName: %s\nVersion: %s\n", resolution.CanonicalReference, resolution.Digest, resolution.Record.Name, resolution.Record.Version)
				return nil
			}
			if lookupErr != nil && !errors.Is(lookupErr, internaladversary.ErrNotFound) {
				return lookupErr
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
			resolver, err := internaladversary.DefaultResolver()
			if err != nil {
				return err
			}
			canonical := artifact.Name + ":" + artifact.Version
			unified, err := resolver.ImportPacked(artifact, canonical)
			if err != nil {
				return err
			}
			latest := artifact.Name + ":" + oci.DefaultTag
			if err := registerExactRef(resolver.Repository, latest, unified.Digest); err != nil {
				return err
			}
			fmt.Fprintln(stdout)
			fmt.Fprintf(stdout, "Name: %s\n", artifact.ManifestName)
			fmt.Fprintf(stdout, "Version: %s\n", artifact.Version)
			fmt.Fprintf(stdout, "Runtime: %s\n", artifact.Runtime)
			if artifact.RuntimeName != "" {
				fmt.Fprintf(stdout, "Runtime Requirement: %s@%s\n", artifact.RuntimeName, artifact.RuntimeVersion)
			}
			fmt.Fprintf(stdout, "Digest: %s\n", unified.Digest)
			fmt.Fprintf(stdout, "Canonical reference: %s\nUnified digest: %s\n", canonical, unified.Digest)
			fmt.Fprintf(stdout, "Size: %s\n", humanSize(artifact.Size))
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "Stored locally as:")
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, canonical)
			fmt.Fprintln(stdout, latest)
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
			resolver, err := internaladversary.DefaultResolver()
			if err != nil {
				return err
			}
			entries, err := resolver.Repository.Entries(10000)
			if err != nil {
				return err
			}
			if opts.json {
				return json.NewEncoder(stdout).Encode(entries)
			}
			if len(entries) == 0 {
				fmt.Fprintln(stdout, "No local adversaries found.")
				return nil
			}
			w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tVERSION\tCANONICAL REFERENCE\tDIGEST")
			for _, entry := range entries {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", entry.Record.Name, entry.Record.Version, entry.CanonicalReference, shortDigest(entry.Digest))
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

func newLoginCommand(stdout, stderr io.Writer, apiURL, profile *string) *cobra.Command {
	opts := &loginOptions{}
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with Adversary Labs",
		Example: `  adversary login
  adversary login --name "Marc's MacBook Pro"
  adversary login --ci
  adversary login --email-address marc@example.com
  printf '%s\n' "$ADVERSARY_PASSWORD" | adversary login --email-address marc@example.com --password-stdin`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := adversarylabs.DefaultConfigStore()
			if err != nil {
				return err
			}
			if _, _, err := store.ExactAuthE(adversarylabs.AuthKey(valueOf(apiURL), valueOf(profile))); err != nil {
				return err
			}
			client := adversarylabs.NewClientWithBaseURL(store, valueOf(apiURL))
			var token adversarylabs.TokenResponse
			if opts.emailAddress != "" || opts.passwordStdin {
				if opts.emailAddress == "" {
					return fmt.Errorf("--email-address is required when --password-stdin is provided")
				}
				var password string
				if opts.passwordStdin {
					password, err = readPasswordLine(os.Stdin)
				} else {
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
			} else if opts.ci || opts.device {
				token, err = loginWithDevice(cmd.Context(), stdout, client, opts)
				if err != nil {
					return err
				}
			} else {
				token, err = loginWithBrowser(cmd.Context(), stdout, client, opts)
				if err != nil {
					return err
				}
			}
			if err := store.SetAuth(adversarylabs.AuthKey(valueOf(apiURL), valueOf(profile)), adversarylabs.Auth{
				Token:             token.Token,
				ClientID:          token.ClientID,
				ExpiresAt:         token.ExpiresAt,
				RegistryNamespace: token.RegistryNamespace,
				Namespace:         token.Namespace,
				Team:              token.Team,
				RegistryHost:      adversarylabs.ResolveRegistryHost(),
			}); err != nil {
				return err
			}
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "Logged in to Adversary Labs.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&opts.ci, "ci", false, "request a short-lived automation token")
	cmd.Flags().BoolVar(&opts.device, "device", false, "use device login for a headless environment")
	cmd.Flags().StringVar(&opts.name, "name", "", "friendly name for this client")
	cmd.Flags().StringVar(&opts.emailAddress, "email-address", "", "email address for password login")
	cmd.Flags().BoolVar(&opts.passwordStdin, "password-stdin", false, "read the password from standard input")
	return cmd
}

func newLogoutCommand(stdout, stderr io.Writer, apiURL, profile *string) *cobra.Command {
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
			key := adversarylabs.AuthKey(valueOf(apiURL), valueOf(profile))
			auth, ok, err := store.ExactAuthE(key)
			if err != nil {
				return err
			}
			if !ok && key == adversarylabs.AuthKey(adversarylabs.DefaultAPIURL, "default") { // exact legacy migration fallback
				auth, ok, err = store.ExactAuthE(adversarylabs.ResolveRegistryHost())
				key = adversarylabs.ResolveRegistryHost()
				if err != nil {
					return err
				}
			}
			if !ok {
				fmt.Fprintln(stdout, "No Adversary Labs login was configured.")
				return nil
			}
			if !opts.localOnly && auth.Token != "" {
				client := adversarylabs.NewClientWithBaseURL(store, valueOf(apiURL))
				if err := client.Revoke(cmd.Context(), auth.Token); err != nil {
					return fmt.Errorf("token revocation failed; local credentials preserved: %w", err)
				}
			}
			if _, _, err := store.RemoveAuth(key); err != nil {
				return err
			}
			fmt.Fprintln(stdout, "Logged out of Adversary Labs.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&opts.localOnly, "local-only", false, "remove local credentials without contacting Adversary Labs")
	return cmd
}

func newPushCommand(stdout, stderr io.Writer, apiURL, profile *string) *cobra.Command {
	return &cobra.Command{
		Use:   "push <local-ref> [remote-ref]",
		Short: "Push a locally packed adversary to an OCI registry",
		Example: `  adversary push dockerfile-reviewer:0.1.0
  adversary push security-reviewer:0.1.0 ghcr.io/acme/security-reviewer:0.1.0
  adversary push sha256:abc123 ghcr.io/acme/security-reviewer:0.1.0
  adversary push ghcr.io/acme/security-reviewer:0.1.0`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if handled, err := pushUnified(cmd.Context(), stdout, stderr, args, valueOf(apiURL), valueOf(profile)); handled {
				return err
			}
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
				remoteRef, err = defaultAdversaryLabsPushRef(cmd.Context(), localRef, record, valueOf(apiURL), valueOf(profile))
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
			registry, err := newOCIRegistry(valueOf(apiURL), valueOf(profile))
			if err != nil {
				return err
			}
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

func pushUnified(ctx context.Context, stdout, stderr io.Writer, args []string, apiURL, profile string) (bool, error) {
	resolver, err := internaladversary.DefaultResolver()
	if err != nil {
		return false, nil
	}
	hasExact, _ := resolver.Repository.HasExact(args[0])
	resolution, err := resolver.Lookup(args[0])
	if err != nil {
		if os.IsNotExist(err) && !hasExact {
			return false, nil
		}
		return true, err
	}
	if resolution.Local {
		return false, nil
	}
	manifest, blobs, yaml, err := resolver.Repository.Payload(resolution.Record)
	if err != nil {
		return true, err
	}
	remote := args[0]
	if len(args) == 2 {
		remote = args[1]
	} else if !hasExplicitRegistry(args[0]) {
		remote, err = defaultAdversaryLabsPushRef(ctx, args[0], store.Record{Name: resolution.Record.Name, ManifestName: resolution.Record.Name, Version: resolution.Record.Version, Digest: resolution.Record.Digest}, apiURL, profile)
		if err != nil {
			return true, err
		}
	}
	ref, err := oci.ParseReference(remote)
	if err != nil {
		return true, err
	}
	registry, err := newOCIRegistry(apiURL, profile)
	if err != nil {
		return true, err
	}
	if ref.Registry == "localhost" || hasLocalhostPort(ref.Registry) {
		registry.PlainHTTP = true
	}
	fmt.Fprintf(stderr, "Pushing %s (%s) to %s\n", resolution.CanonicalReference, resolution.Digest, ref.Locator())
	digest, err := registry.Push(ctx, ref, manifest, blobs)
	if err != nil {
		return true, err
	}
	artifactDigest, _, err := registry.PushAdversaryManifestReferrer(ctx, ref, digest, yaml)
	if err != nil {
		return true, err
	}
	if err := registerExactRef(resolver.Repository, ref.Locator(), digest); err != nil {
		return true, err
	}
	fmt.Fprintf(stdout, "Canonical reference: %s\nImage digest\n\n%s\nDigest: %s\nPublished adversary manifest referrer\n\n%s\n", ref.Locator(), digest, digest, artifactDigest)
	return true, nil
}

func newPullCommand(stdout, stderr io.Writer, apiURL, profile *string) *cobra.Command {
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
			registry, err := newOCIRegistry(valueOf(apiURL), valueOf(profile))
			if err != nil {
				return err
			}
			if ref.Registry == "localhost" || hasLocalhostPort(ref.Registry) {
				registry.PlainHTTP = true
			}
			fmt.Fprintln(stderr, "Pulling manifest...")
			fmt.Fprintln(stderr)
			digest, err := registry.Resolve(cmd.Context(), ref)
			if err != nil {
				return err
			}
			resolver, resolverErr := internaladversary.DefaultResolver()
			if resolverErr == nil {
				if existing, resolveErr := resolver.Repository.Resolve(digest); resolveErr == nil {
					if err := registerExactRef(resolver.Repository, ref.Locator(), existing.Digest); err != nil {
						return err
					}
					fmt.Fprintf(stdout, "Installed: %s\nVersion: %s\nCanonical reference: %s\nDigest: %s\n", existing.Name, existing.Version, ref.Locator(), existing.Digest)
					return nil
				} else if !os.IsNotExist(resolveErr) {
					return resolveErr
				}
			}
			fmt.Fprintln(stderr, "Downloading layers...")
			artifact, err := registry.Pull(cmd.Context(), ref)
			if err != nil {
				return err
			}
			if resolverErr != nil {
				return resolverErr
			}
			unified, err := resolver.ImportPulled(artifact)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Installed: %s\nVersion: %s\nCanonical reference: %s\nDigest: %s\n", unified.Name, unified.Version, ref.Locator(), unified.Digest)
			return nil
		},
	}
}
func registerExactRef(repo repository.Repository, ref, digest string) error {
	current, err := repo.Resolve(ref)
	if err == nil {
		if current.Digest == digest {
			return nil
		}
		return fmt.Errorf("%w: %s currently points to %s", repository.ErrCAS, ref, current.Digest)
	}
	if !os.IsNotExist(err) {
		return err
	}
	return repo.UpdateRef(ref, "", digest)
}

func newSearchCommand(stdout, stderr io.Writer, apiURL, profile *string) *cobra.Command {
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
			auth, ok, err := scopedAuth(store, valueOf(apiURL), valueOf(profile))
			if err != nil {
				return err
			}
			if ok {
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

func newWhoamiCommand(stdout, stderr io.Writer, apiURL, profile *string) *cobra.Command {
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
			auth, ok, err := scopedAuth(store, valueOf(apiURL), valueOf(profile))
			if err != nil {
				return err
			}
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
	expiresAt := time.Now().Add(time.Duration(login.ExpiresIn) * time.Second)
	if login.ExpiresIn <= 0 {
		expiresAt = time.Now().Add(10 * time.Minute)
	}
	pollCtx, cancel := context.WithDeadline(ctx, expiresAt)
	defer cancel()
	for {
		if err := pollCtx.Err(); err != nil {
			if ctx.Err() != nil {
				return adversarylabs.TokenResponse{}, ctx.Err()
			}
			return adversarylabs.TokenResponse{}, fmt.Errorf("login expired before authentication completed")
		}
		token, err := client.PollToken(pollCtx, login.DeviceCode)
		if err == nil {
			return token, nil
		}
		if pollCtx.Err() != nil {
			if ctx.Err() != nil {
				return adversarylabs.TokenResponse{}, ctx.Err()
			}
			return adversarylabs.TokenResponse{}, fmt.Errorf("login expired before authentication completed")
		}
		timer := time.NewTimer(interval)
		select {
		case <-pollCtx.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return adversarylabs.TokenResponse{}, ctx.Err()
			}
			return adversarylabs.TokenResponse{}, fmt.Errorf("login expired before authentication completed")
		case <-timer.C:
		}
	}
}

func loginWithDevice(ctx context.Context, stdout io.Writer, client adversarylabs.Client, opts *loginOptions) (adversarylabs.TokenResponse, error) {
	login, err := client.BeginLogin(ctx, adversarylabs.LoginOptions{Name: opts.name, CI: opts.ci})
	if err != nil {
		return adversarylabs.TokenResponse{}, err
	}
	verificationURL := login.VerificationURIComplete
	if verificationURL == "" {
		verificationURL = login.VerificationURI
	}
	if verificationURL == "" || login.UserCode == "" {
		return adversarylabs.TokenResponse{}, fmt.Errorf("device login response was missing verification instructions")
	}
	fmt.Fprintf(stdout, "Open %s\n\nEnter code: %s\n\nWaiting for authentication...\n", verificationURL, login.UserCode)
	return waitForLogin(ctx, client, login)
}

func loginWithBrowser(ctx context.Context, stdout io.Writer, client adversarylabs.Client, opts *loginOptions) (adversarylabs.TokenResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	state, err := randomURLToken(32)
	if err != nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("generate login state: %w", err)
	}
	verifier, err := randomURLToken(48)
	if err != nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("generate PKCE verifier: %w", err)
	}
	pathToken, err := randomURLToken(24)
	if err != nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("generate callback path: %w", err)
	}
	callbackPath := "/callback/" + pathToken
	challengeBytes := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("start local login callback: %w", err)
	}
	defer listener.Close()

	result := make(chan browserLoginOutcome, 1)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second}
	mux := http.NewServeMux()
	server.Handler = mux
	callbackURL := "http://" + listener.Addr().String() + callbackPath
	mux.Handle(callbackPath, browserCallbackHandler(state, result, func(code string) (adversarylabs.TokenResponse, error) {
		return client.ExchangeCode(ctx, code, verifier, callbackURL)
	}))
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			publishBrowserOutcome(result, browserLoginOutcome{err: err})
		}
	}()
	defer func() {
		shutdownCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		_ = server.Shutdown(shutdownCtx)
	}()

	loginURL, err := client.BrowserLoginURL(adversarylabs.BrowserLoginOptions{
		RedirectURI:   callbackURL,
		State:         state,
		CodeChallenge: challenge,
		Name:          opts.name,
		CI:            opts.ci,
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
	case outcome := <-result:
		return outcome.token, outcome.err
	case <-ctx.Done():
		return adversarylabs.TokenResponse{}, ctx.Err()
	}
}

type browserLoginOutcome struct {
	token adversarylabs.TokenResponse
	err   error
}

func publishBrowserOutcome(ch chan<- browserLoginOutcome, outcome browserLoginOutcome) {
	select {
	case ch <- outcome:
	default:
	}
}

func browserCallbackHandler(state string, result chan<- browserLoginOutcome, exchange func(string) (adversarylabs.TokenResponse, error)) http.Handler {
	var once sync.Once
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
			return
		}
		query := req.URL.Query()
		if query.Get("state") != state {
			http.Error(w, "Invalid login state.", http.StatusBadRequest)
			return
		}
		if query.Get("error") != "" {
			handled := false
			once.Do(func() {
				handled = true
				publishBrowserOutcome(result, browserLoginOutcome{err: fmt.Errorf("login authorization failed")})
				http.Error(w, "Login failed. You can close this window.", http.StatusBadRequest)
			})
			if !handled {
				http.Error(w, "Login callback was already handled.", http.StatusConflict)
			}
			return
		}
		code := query.Get("code")
		if code == "" || query.Get("token") != "" {
			http.Error(w, "Login callback was missing a code.", http.StatusBadRequest)
			return
		}
		handled := false
		once.Do(func() {
			handled = true
			token, err := exchange(code)
			if err != nil {
				publishBrowserOutcome(result, browserLoginOutcome{err: err})
				http.Error(w, "Login failed. You can close this window.", http.StatusBadGateway)
				return
			}
			publishBrowserOutcome(result, browserLoginOutcome{token: token})
			fmt.Fprintln(w, "Login complete. You can close this window.")
		})
		if !handled {
			http.Error(w, "Login callback was already handled.", http.StatusConflict)
		}
	})
}

func randomURLToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func readPasswordLine(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, 64*1024))
	if err != nil {
		return "", err
	}
	password := strings.TrimRight(string(data), "\r\n")
	if password == "" {
		return "", fmt.Errorf("password from standard input is empty")
	}
	return password, nil
}

func promptPassword(stderr io.Writer) (string, error) {
	fmt.Fprint(stderr, "Password: ")
	if term.IsTerminal(int(os.Stdin.Fd())) {
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(stderr)
		return string(password), err
	}
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("no interactive terminal; use --password-stdin")
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("no interactive terminal; use --password-stdin")
	}
	defer tty.Close()
	password, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(stderr)
	if err != nil {
		return "", err
	}
	return string(password), nil
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

type scopedCredentialStore struct{ registry, token string }

func (s scopedCredentialStore) Credentials(registry string) (oci.Credentials, bool) {
	if registry != s.registry || s.token == "" {
		return oci.Credentials{}, false
	}
	return oci.Credentials{Token: s.token}, true
}

func scopedAuth(store adversarylabs.ConfigStore, apiURL, profile string) (adversarylabs.Auth, bool, error) {
	key := adversarylabs.AuthKey(apiURL, profile)
	auth, ok, err := store.ExactAuthE(key)
	if err != nil || ok {
		return auth, ok, err
	}
	if key == adversarylabs.AuthKey(adversarylabs.DefaultAPIURL, "default") {
		return store.ExactAuthE(adversarylabs.ResolveRegistryHost())
	}
	return adversarylabs.Auth{}, false, nil
}

func newOCIRegistry(apiURL, profile string) (*oci.HTTPRegistry, error) {
	registry := oci.NewHTTPRegistry()
	if strings.TrimSpace(os.Getenv("ADVERSARY_OCI_DEBUG")) != "" {
		registry.Debug = os.Stderr
	}
	registry.BearerRealm = registryAuthRealm(apiURL)
	registry.BearerService = adversarylabs.ResolveRegistryHost()
	store, err := adversarylabs.DefaultConfigStore()
	if err != nil {
		return nil, err
	}
	auth, ok, err := scopedAuth(store, apiURL, profile)
	if err != nil {
		return nil, err
	}
	stores := oci.ChainCredentialStore{oci.DockerCredentialStore{}}
	if ok {
		stores = append(oci.ChainCredentialStore{scopedCredentialStore{registry: adversarylabs.ResolveRegistryHost(), token: auth.Token}}, stores...)
	}
	registry.Credentials = stores
	return registry, nil
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

func defaultAdversaryLabsPushRef(ctx context.Context, localRef string, record store.Record, apiURL, profile string) (string, error) {
	configStore, err := adversarylabs.DefaultConfigStore()
	if err != nil {
		return "", err
	}
	registryHost := adversarylabs.ResolveRegistryHost()
	auth, ok, err := scopedAuth(configStore, apiURL, profile)
	if err != nil {
		return "", err
	}
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
