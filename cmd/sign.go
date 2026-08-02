package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/officialsig"
	"github.com/spf13/cobra"
)

func newSignCommand(app *application.App, apiURL, profile *string) *cobra.Command {
	var keyID string
	var digestFlag string
	var seedFlag string
	var format string
	cmd := &cobra.Command{
		Use:   "sign <remote-reference>",
		Short: "Sign a published adversary and attach the official signature referrer",
		Long: `Create an official catalog signature for a remote artifact digest and push it
as an OCI referrer.

Signing seed (private, never commit):
  --seed <hex>                    flag (highest precedence)
  ADVERSARY_OFFICIAL_SIGNING_SEED environment variable

Key id defaults to this binary's build flavor:
  go build               → official-dev
  go build -tags release → official-prod

Requires registry credentials (adversary login or service account profile).
End users never need this command; publishers use it after push.`,
		Example: `  # Local/dev (seed from Doppler)
  doppler run -p adversarylabs -c dev -- \
    adversary sign localhost:8787/adversarylabs/adversary:0.0.22 --key-id official-dev

  # Or explicit seed flag
  adversary sign registry…/adversarylabs/adversary:0.0.22 \
    --seed "$ADVERSARY_OFFICIAL_SIGNING_SEED" --key-id official-prod

  # Production CI
  adversary sign registry.adversarylabs.ai/adversarylabs/adversary:0.0.22 \
    --key-id official-prod`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			seed := strings.TrimSpace(seedFlag)
			if seed == "" {
				seed = officialsig.SigningSeedFromEnv()
			}
			if seed == "" {
				return &application.Error{
					Operation: "sign",
					Kind:      "usage",
					Err: fmt.Errorf(
						"signing seed required via --seed or ADVERSARY_OFFICIAL_SIGNING_SEED (never commit this value)",
					),
				}
			}
			priv, err := officialsig.ParsePrivateKeySeed(seed)
			if err != nil {
				return &application.Error{Operation: "sign", Kind: "usage", Err: err}
			}
			if keyID == "" {
				keyID = officialsig.DefaultKeyID
			}

			ref, err := app.Dependencies().References.Parse(args[0])
			if err != nil {
				return err
			}
			registry, err := app.Dependencies().Registries.New(valueOf(apiURL), valueOf(profile))
			if err != nil {
				return err
			}
			if ref.Registry == "localhost" || hasLocalhostPort(ref.Registry) {
				registry.SetPlainHTTP(true)
			}

			digest := strings.TrimSpace(digestFlag)
			if digest == "" && ref.Digest != "" {
				digest = ref.Digest
			}
			if digest == "" {
				resolved, resolveErr := registry.Resolve(cmd.Context(), ref)
				if resolveErr != nil {
					return &application.Error{
						Operation: "sign",
						Kind:      "network",
						Resource:  ref.Locator(),
						Err:       resolveErr,
					}
				}
				digest = resolved
			}

			env, err := officialsig.Sign(digest, keyID, priv, time.Now().UTC())
			if err != nil {
				return err
			}
			raw, err := officialsig.MarshalEnvelope(env)
			if err != nil {
				return err
			}

			sigDigest, _, err := registry.PushAttachedReferrer(
				cmd.Context(),
				ref,
				digest,
				oci.OfficialSignatureMediaType,
				"official-signature.json",
				officialsig.ArtifactTagKind,
				raw,
			)
			if err != nil {
				return &application.Error{
					Operation: "sign",
					Kind:      "network",
					Resource:  ref.Locator(),
					Err:       err,
				}
			}

			if saveErr := app.Dependencies().Repository.SaveOfficialSignature(digest, raw); saveErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not cache signature locally: %v\n", saveErr)
			}

			if format == "json" {
				return writeJSON(cmd.OutOrStdout(), "sign", map[string]string{
					"reference":       ref.Locator(),
					"subjectDigest":   digest,
					"keyID":           keyID,
					"signatureDigest": sigDigest,
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Signed %s\nSubject digest: %s\nKey id: %s\nSignature referrer digest: %s\n",
				ref.Locator(), digest, keyID, sigDigest)
			return nil
		},
	}
	cmd.Flags().StringVar(&seedFlag, "seed", "", "Ed25519 signing seed hex (or set ADVERSARY_OFFICIAL_SIGNING_SEED)")
	cmd.Flags().StringVar(&keyID, "key-id", "", "key id (default: official-dev or official-prod for this binary)")
	cmd.Flags().StringVar(&digestFlag, "digest", "", "subject image digest (default: resolve remote tag)")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}
