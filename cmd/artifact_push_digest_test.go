package cmd

import (
	"bytes"
	"context"
	"crypto/sha512"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/blobsource"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/adversarylabs/adversary/pkg/repository"
)

func TestPushCommitsRegistryDigestWhenAlgorithmChanges(t *testing.T) {
	remote := newTestOCIRegistry()
	server := httptest.NewServer(remote)
	defer server.Close()

	project := t.TempDir()
	writeProject(t, project)
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: project})
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Close()
	blobs, err := artifact.Sources()
	if err != nil {
		t.Fatal(err)
	}
	localDigest := fmt.Sprintf("sha512:%x", sha512.Sum512(artifact.Manifest))
	manifestSource, err := blobsource.New(int64(len(artifact.Manifest)), localDigest, func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(artifact.Manifest)), nil
	})
	if err != nil {
		t.Fatal(err)
	}

	repo := repository.Repository{Root: t.TempDir()}
	generic := "security-reviewer:1.4.2"
	local, err := repo.ImportSources(repository.SourceImport{Reference: generic, Name: artifact.ManifestName, Version: artifact.Version, Manifest: manifestSource, Blobs: blobs, AdversaryManifest: blobsource.Bytes(artifact.AdversaryManifest)})
	if err != nil {
		t.Fatal(err)
	}
	if local.Digest != localDigest {
		t.Fatalf("local digest=%s", local.Digest)
	}
	remoteRef := strings.TrimPrefix(server.URL, "http://") + "/acme/security-reviewer:v1"
	if err := repo.UpdateRef(remoteRef, "", localDigest); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := lifecycleTestApp(t, repo, &stdout, &stderr)
	root := NewRootCommandWithApp(app)
	root.SetArgs([]string{"push", generic, remoteRef})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	remoteDigest := oci.Digest(remote.manifest(t, "acme/security-reviewer/v1"))
	if !strings.HasPrefix(remoteDigest, "sha256:") || !strings.Contains(stdout.String(), remoteDigest) {
		t.Fatalf("remote digest=%s output=%q", remoteDigest, stdout.String())
	}
	if got, err := repo.Resolve(remoteRef); err != nil || got.Digest != remoteDigest {
		t.Fatalf("remote record=%#v err=%v", got, err)
	}
	if got, err := repo.Resolve(remoteDigest); err != nil || got.Digest != remoteDigest {
		t.Fatalf("digest record=%#v err=%v", got, err)
	}
	if got, err := repo.Resolve(generic); err != nil || got.Digest != localDigest {
		t.Fatalf("generic record changed: %#v err=%v", got, err)
	}
	if got, err := repo.Resolve(localDigest); err != nil || got.Digest != localDigest {
		t.Fatalf("original record missing: %#v err=%v", got, err)
	}
	for _, alias := range []string{artifact.ManifestName, artifact.ManifestName + ":" + artifact.Version} {
		if got, err := repo.Resolve(alias); err != nil || got.Digest != localDigest {
			t.Fatalf("equivalent alias %q=%#v err=%v", alias, got, err)
		}
	}
}

type pushDigestFixture struct {
	repo                            repository.Repository
	app                             *application.App
	localDigest, generic, remoteRef string
	manifestName, version           string
}

func makePushDigestFixture(t *testing.T, registry http.Handler) pushDigestFixture {
	t.Helper()
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	project := t.TempDir()
	writeProject(t, project)
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: project})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = artifact.Close() })
	blobs, err := artifact.Sources()
	if err != nil {
		t.Fatal(err)
	}
	localDigest := fmt.Sprintf("sha512:%x", sha512.Sum512(artifact.Manifest))
	manifestSource, err := blobsource.New(int64(len(artifact.Manifest)), localDigest, func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(artifact.Manifest)), nil })
	if err != nil {
		t.Fatal(err)
	}
	repo := repository.Repository{Root: t.TempDir()}
	generic := "security-reviewer:1.4.2"
	if _, err := repo.ImportSources(repository.SourceImport{Reference: generic, Name: artifact.ManifestName, Version: artifact.Version, Manifest: manifestSource, Blobs: blobs, AdversaryManifest: blobsource.Bytes(artifact.AdversaryManifest)}); err != nil {
		t.Fatal(err)
	}
	remoteRef := strings.TrimPrefix(server.URL, "http://") + "/acme/security-reviewer:v1"
	if err := repo.UpdateRef(remoteRef, "", localDigest); err != nil {
		t.Fatal(err)
	}
	app := lifecycleTestApp(t, repo, &bytes.Buffer{}, &bytes.Buffer{})
	return pushDigestFixture{repo: repo, app: app, localDigest: localDigest, generic: generic, remoteRef: remoteRef, manifestName: artifact.ManifestName, version: artifact.Version}
}

type casFailResolver struct {
	application.Resolver
	ref string
}

func (r casFailResolver) UpdateRef(ref, oldDigest, newDigest string) error {
	if ref == r.ref {
		return repository.ErrCAS
	}
	return r.Resolver.UpdateRef(ref, oldDigest, newDigest)
}

func TestPushDigestCanonicalizationFailureDoesNotRetargetReference(t *testing.T) {
	for name, configure := range map[string]func(*testing.T, *testOCIRegistry) (http.Handler, func(application.Resolver) application.Resolver){
		"referrer failure": func(t *testing.T, registry *testOCIRegistry) (http.Handler, func(application.Resolver) application.Resolver) {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method == http.MethodPut && req.Header.Get("Content-Type") == oci.OCIArtifactManifestMediaType {
					http.Error(w, "fixture", http.StatusInternalServerError)
					return
				}
				registry.ServeHTTP(w, req)
			}), func(r application.Resolver) application.Resolver { return r }
		},
		"reference CAS failure": func(t *testing.T, registry *testOCIRegistry) (http.Handler, func(application.Resolver) application.Resolver) {
			return registry, func(r application.Resolver) application.Resolver { return casFailResolver{Resolver: r} }
		},
	} {
		t.Run(name, func(t *testing.T) {
			registry := newTestOCIRegistry()
			handler, wrap := configure(t, registry)
			fixture := makePushDigestFixture(t, handler)
			resolver := wrap(fixture.app.Dependencies().Resolver)
			if wrapped, ok := resolver.(casFailResolver); ok {
				wrapped.ref = fixture.remoteRef
				resolver = wrapped
			}
			var stdout, stderr bytes.Buffer
			_, err := pushUnified(context.Background(), fixture.app, resolver, &stdout, &stderr, []string{fixture.generic, fixture.remoteRef}, "", "", "text")
			if err == nil {
				t.Fatal("push unexpectedly succeeded")
			}
			if got, resolveErr := fixture.repo.Resolve(fixture.remoteRef); resolveErr != nil || got.Digest != fixture.localDigest {
				t.Fatalf("remote ref changed: %#v err=%v", got, resolveErr)
			}
			if got, resolveErr := fixture.repo.Resolve(fixture.localDigest); resolveErr != nil || got.Digest != fixture.localDigest {
				t.Fatalf("source record missing: %#v err=%v", got, resolveErr)
			}
			remoteDigest := oci.Digest(registry.manifest(t, "acme/security-reviewer/v1"))
			if got, resolveErr := fixture.repo.Resolve(remoteDigest); resolveErr != nil || got.Digest != remoteDigest {
				t.Fatalf("equivalent record missing: %#v err=%v", got, resolveErr)
			}
		})
	}
}
