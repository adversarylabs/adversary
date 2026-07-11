package cmd

import (
	"context"
	"errors"
	"fmt"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/oci"
	"net/http"
	"strings"
)

type scopedCredentialStore struct{ registry, token string }

func (s scopedCredentialStore) Credentials(registry string) (oci.Credentials, bool) {
	if registry != s.registry || s.token == "" {
		return oci.Credentials{}, false
	}
	return oci.Credentials{Token: s.token}, true
}

func scopedAuth(store application.AuthStore, apiURL, profile, registryHost string) (adversarylabs.Auth, bool, error) {
	key := adversarylabs.AuthKey(apiURL, profile)
	auth, ok, err := store.ExactAuthE(key)
	if err != nil || ok {
		return auth, ok, err
	}
	if key == adversarylabs.AuthKey(adversarylabs.DefaultAPIURL, "default") {
		return store.ExactAuthE(registryHost)
	}
	return adversarylabs.Auth{}, false, nil
}

func registryAuthRealm(apiURL string) string {
	base := strings.TrimRight(apiURL, "/")
	base = strings.TrimSuffix(base, "/api")
	return base + "/auth/registry"
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

type pushRecord struct{ Name, ManifestName, Version, Digest string }

func defaultAdversaryLabsPushRef(ctx context.Context, deps application.Dependencies, localRef string, record pushRecord, apiURL, profile string) (string, error) {
	registryHost := deps.RegistryHost
	auth, ok, err := scopedAuth(deps.Auth, apiURL, profile, registryHost)
	if err != nil {
		return "", err
	}
	if !ok {
		if registryHost != adversarylabs.DefaultRegistry {
			namespace := cleanRegistryNamespace(deps.RegistryNS)
			if namespace == "" {
				namespace = oci.DefaultNamespace
			}
			return defaultRegistryPushRef(registryHost, namespace, record), nil
		}
		return "", fmt.Errorf("remote reference is required for unqualified local ref %q; run adversary login or provide a remote reference", localRef)
	}
	namespace := registryNamespaceFromAuth(auth, deps.RegistryNS)
	if namespace == "" {
		client := deps.API.New(apiURL)
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

func defaultRegistryPushRef(registryHost, namespace string, record pushRecord) string {
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
	var registryErr *oci.RegistryError
	if !errors.As(err, &registryErr) {
		return false
	}
	if registryErr.StatusCode == http.StatusForbidden {
		return true
	}
	for _, code := range registryErr.Codes {
		if strings.EqualFold(code.Code, "DENIED") || strings.EqualFold(code.Code, "UNAUTHORIZED") {
			return true
		}
	}
	return false
}

func registryNamespaceFromReference(ref oci.Reference) string {
	namespace, _, ok := strings.Cut(ref.Repository, "/")
	if !ok {
		return ""
	}
	return namespace
}

func registryNamespaceFromAuth(auth adversarylabs.Auth, configured string) string {
	for _, value := range []string{
		configured,
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
