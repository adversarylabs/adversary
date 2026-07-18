package cmd

import (
	"fmt"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/spf13/cobra"
)

type loginOptions struct {
	ci                                    bool
	name, emailAddress, registryNamespace string
	passwordStdin, tokenStdin, device     bool
}
type logoutOptions struct{ localOnly bool }

func newLoginCommand(app *application.App, apiURL, profile *string) *cobra.Command {
	opts := &loginOptions{}
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with Adversary Labs",
		Example: `  adversary login
  adversary login --name "Marc's MacBook Pro"
  adversary login --ci
  printf '%s\n' "$ADVERSARY_SERVICE_TOKEN" | adversary login --token-stdin --registry-namespace my-team
  adversary login --email-address marc@example.com
  printf '%s\n' "$ADVERSARY_PASSWORD" | adversary login --email-address marc@example.com --password-stdin`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			deps := app.Dependencies()
			stdin, clock, browserAuth, tty := cmd.InOrStdin(), deps.Clock, deps.BrowserAuth, deps.TTY
			store := deps.Auth
			var err error
			if _, _, err := store.ExactAuthE(adversarylabs.AuthKey(valueOf(apiURL), valueOf(profile))); err != nil {
				return err
			}
			client := deps.API.New(valueOf(apiURL))
			var token adversarylabs.TokenResponse
			if opts.tokenStdin {
				if opts.emailAddress != "" || opts.passwordStdin || opts.device || opts.ci {
					return fmt.Errorf("--token-stdin cannot be combined with password, device, or CI login options")
				}
				value, readErr := readSecretLine(stdin, "token")
				if readErr != nil {
					return readErr
				}
				token = adversarylabs.TokenResponse{Token: value, RegistryNamespace: opts.registryNamespace}
			} else if opts.emailAddress != "" || opts.passwordStdin {
				if opts.registryNamespace != "" {
					return fmt.Errorf("--registry-namespace requires --token-stdin")
				}
				if opts.emailAddress == "" {
					return fmt.Errorf("--email-address is required when --password-stdin is provided")
				}
				var password string
				if opts.passwordStdin {
					password, err = readPasswordLine(stdin)
				} else {
					secret, secretErr := tty.ReadSecret(cmd.Context(), stdin, cmd.ErrOrStderr())
					err = secretErr
					password = string(secret)
					for i := range secret {
						secret[i] = 0
					}
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
				if opts.registryNamespace != "" {
					return fmt.Errorf("--registry-namespace requires --token-stdin")
				}
				token, err = loginWithDevice(cmd.Context(), clock, cmd.OutOrStdout(), client, opts)
				if err != nil {
					return err
				}
			} else {
				if opts.registryNamespace != "" {
					return fmt.Errorf("--registry-namespace requires --token-stdin")
				}
				token, err = browserAuth.Login(cmd.Context(), application.BrowserAuthRequest{Client: client, Name: opts.name, CI: opts.ci, Output: cmd.OutOrStdout()})
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
				RegistryHost:      deps.RegistryHost,
			}); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "Logged in to Adversary Labs.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&opts.ci, "ci", false, "request a short-lived automation token")
	cmd.Flags().BoolVar(&opts.device, "device", false, "use device login for a headless environment")
	cmd.Flags().StringVar(&opts.name, "name", "", "friendly name for this client")
	cmd.Flags().StringVar(&opts.emailAddress, "email-address", "", "email address for password login")
	cmd.Flags().BoolVar(&opts.passwordStdin, "password-stdin", false, "read the password from standard input")
	cmd.Flags().BoolVar(&opts.tokenStdin, "token-stdin", false, "read a service account token from standard input")
	cmd.Flags().StringVar(&opts.registryNamespace, "registry-namespace", "", "registry namespace for a service account token")
	return cmd
}

func newLogoutCommand(app *application.App, apiURL, profile *string) *cobra.Command {
	opts := &logoutOptions{}
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Log out of Adversary Labs",
		Example: `  adversary logout
  adversary logout --local-only`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			deps := app.Dependencies()
			store := deps.Auth
			key := adversarylabs.AuthKey(valueOf(apiURL), valueOf(profile))
			auth, ok, err := store.ExactAuthE(key)
			if err != nil {
				return err
			}
			if !ok && key == adversarylabs.AuthKey(adversarylabs.DefaultAPIURL, "default") { // exact legacy migration fallback
				auth, ok, err = store.ExactAuthE(deps.RegistryHost)
				key = deps.RegistryHost
				if err != nil {
					return err
				}
			}
			if !ok {
				fmt.Fprintln(cmd.OutOrStdout(), "No Adversary Labs login was configured.")
				return nil
			}
			if !opts.localOnly && auth.Token != "" {
				client := deps.API.New(valueOf(apiURL))
				if err := client.Revoke(cmd.Context(), auth.Token); err != nil {
					return fmt.Errorf("token revocation failed; local credentials preserved: %w", err)
				}
			}
			if err := store.RemoveAuthCAS(key, auth); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Logged out of Adversary Labs.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&opts.localOnly, "local-only", false, "remove local credentials without contacting Adversary Labs")
	return cmd
}
