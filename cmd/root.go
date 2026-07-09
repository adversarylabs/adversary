package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/initproject"
	"github.com/adversarylabs/adversary/internal/version"
	adversarypkg "github.com/adversarylabs/adversary/pkg/adversary"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/oci"
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
		Short:         "Run containerized source-code adversaries against a local repository",
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
	cmd.AddCommand(newVersionCommand(stdout))
	cmd.AddCommand(newLoginCommand(stdout, stderr, &apiURL))
	cmd.AddCommand(newLogoutCommand(stdout, stderr, &apiURL))
	cmd.AddCommand(newPushCommand(stdout, stderr))
	cmd.AddCommand(newPullCommand(stdout, stderr))
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
	build     bool
	noBuild   bool
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
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --shell
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --no-build`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.format != "text" && opts.format != "json" {
				return fmt.Errorf("--format must be text or json")
			}
			if opts.build && opts.noBuild {
				return fmt.Errorf("--build and --no-build cannot be used together")
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
				Build:        opts.build,
				NoBuild:      opts.noBuild,
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
	cmd.Flags().BoolVar(&opts.noNetwork, "no-network", false, "force container network disabled")
	cmd.Flags().BoolVar(&opts.build, "build", false, "build a local directory adversary image before running")
	cmd.Flags().BoolVar(&opts.noBuild, "no-build", false, "skip building a local directory adversary image")
	cmd.Flags().BoolVar(&opts.verbose, "verbose", false, "print detailed execution diagnostics")
	cmd.Flags().BoolVar(&opts.shell, "shell", false, "launch an interactive shell in the configured container")
	cmd.Flags().BoolVar(&opts.allFiles, "all-files", false, "scan all files even when diff refs are provided")

	return cmd
}

func newInspectCommand(stdout, stderr io.Writer) *cobra.Command {
	opts := &runOptions{}

	cmd := &cobra.Command{
		Use:   "inspect <adversary-ref>",
		Short: "Inspect a local adversary runtime configuration",
		Example: `  adversary inspect ./smoke-tests/comment-sentence-adversary --repo .
  adversary inspect adversarylabs/dockerfile --repo .`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
	cmd.Flags().BoolVar(&opts.noNetwork, "no-network", false, "force container network disabled")

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
			if err := store.SetAuth(adversarylabs.DefaultRegistry, adversarylabs.Auth{
				Token:     token.Token,
				ClientID:  token.ClientID,
				ExpiresAt: token.ExpiresAt,
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
			auth, ok, err := store.RemoveAuth(adversarylabs.DefaultRegistry)
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

func newPushCommand(stdout, stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "push <reference>",
		Short: "Package and push the current adversary to an OCI registry",
		Example: `  adversary push security-reviewer
  adversary push adversarylabs/security-reviewer
  adversary push ghcr.io/acme/security-reviewer
  adversary push localhost:5000/security-reviewer`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref, err := oci.ParseReference(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintln(stderr, "Packaging adversary...")
			pkg, err := adversarypkg.PackageDirectory(".")
			if err != nil {
				return err
			}
			manifest, _, err := adversarypkg.BuildOCIManifest(pkg)
			if err != nil {
				return err
			}
			registry := newOCIRegistry()
			if ref.Registry == "localhost" || hasLocalhostPort(ref.Registry) {
				registry.PlainHTTP = true
			}
			fmt.Fprintln(stderr, "Pushing layers...")
			fmt.Fprintln(stderr, "Pushing manifest...")
			digest, err := registry.Push(cmd.Context(), ref, manifest, pkg.Blobs())
			if err != nil {
				return err
			}
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "Published:")
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, ref.Locator())
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "Digest:")
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, digest)
			return nil
		},
	}
}

func newPullCommand(stdout, stderr io.Writer) *cobra.Command {
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
			registry := newOCIRegistry()
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
			if auth, ok := store.Auth(adversarylabs.DefaultRegistry); ok {
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
			auth, ok := store.Auth(adversarylabs.DefaultRegistry)
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

func newOCIRegistry() *oci.HTTPRegistry {
	registry := oci.NewHTTPRegistry()
	store, err := adversarylabs.DefaultConfigStore()
	if err == nil {
		registry.Credentials = oci.ChainCredentialStore{store, oci.DockerCredentialStore{}}
	}
	return registry
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
