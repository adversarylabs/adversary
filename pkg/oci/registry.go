package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Blob struct {
	Descriptor Descriptor
	Data       []byte
}

type Registry interface {
	Push(ctx context.Context, ref Reference, manifest []byte, blobs []Blob) (string, error)
	Pull(ctx context.Context, ref Reference) (PulledArtifact, error)
	Resolve(ctx context.Context, ref Reference) (string, error)
}

type HTTPRegistry struct {
	Client        *http.Client
	Credentials   CredentialStore
	PlainHTTP     bool
	Debug         io.Writer
	BearerRealm   string
	BearerService string
}

func NewHTTPRegistry() *HTTPRegistry {
	return &HTTPRegistry{
		Client:      http.DefaultClient,
		Credentials: DockerCredentialStore{},
	}
}

func (r *HTTPRegistry) Push(ctx context.Context, ref Reference, manifest []byte, blobs []Blob) (string, error) {
	for _, blob := range blobs {
		if err := VerifyDigest(blob.Data, blob.Descriptor.Digest); err != nil {
			return "", err
		}
		if err := r.pushBlob(ctx, ref, blob); err != nil {
			return "", err
		}
	}
	return r.pushManifest(ctx, ref, ref.ManifestReference(), ImageManifestMediaType, manifest)
}

func (r *HTTPRegistry) PushAdversaryManifestReferrer(ctx context.Context, imageRef Reference, imageDigest string, yaml []byte) (string, string, error) {
	yamlBlob := Blob{
		Descriptor: Descriptor{
			MediaType: AdversaryManifestMediaType,
			Digest:    Digest(yaml),
			Size:      int64(len(yaml)),
		},
		Data: yaml,
	}
	if err := r.pushBlob(ctx, imageRef, yamlBlob); err != nil {
		return "", "", err
	}
	artifactManifest, _, _, err := NewAdversaryManifestArtifact(imageDigest, yaml)
	if err != nil {
		return "", "", err
	}
	artifactTag, err := AdversaryManifestArtifactTag(imageDigest)
	if err != nil {
		return "", "", err
	}
	digest, err := r.pushManifest(ctx, imageRef, artifactTag, OCIArtifactManifestMediaType, artifactManifest)
	if err != nil {
		return "", "", err
	}
	return digest, artifactTag, nil
}

func (r *HTTPRegistry) pushManifest(ctx context.Context, ref Reference, manifestReference, mediaType string, manifest []byte) (string, error) {
	digest := Digest(manifest)
	req, err := r.newRequest(ctx, http.MethodPut, ref, "/manifests/"+manifestReference, bytes.NewReader(manifest))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", mediaType)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(manifest)))
	resp, err := r.do(req, ref, "repository:"+ref.Repository+":push,pull")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", registryError(resp)
	}
	if got := resp.Header.Get("Docker-Content-Digest"); got != "" {
		digest = got
	}
	return digest, nil
}

func (r *HTTPRegistry) Pull(ctx context.Context, ref Reference) (PulledArtifact, error) {
	manifestData, manifestDigest, err := r.getManifest(ctx, ref)
	if err != nil {
		return PulledArtifact{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return PulledArtifact{}, err
	}
	if manifest.MediaType != "" && manifest.MediaType != ImageManifestMediaType {
		return PulledArtifact{}, fmt.Errorf("unsupported manifest media type %s", manifest.MediaType)
	}
	blobs := map[string][]byte{}
	descriptors := append([]Descriptor{manifest.Config}, manifest.Layers...)
	for _, descriptor := range descriptors {
		data, err := r.getBlob(ctx, ref, descriptor)
		if err != nil {
			return PulledArtifact{}, err
		}
		blobs[descriptor.Digest] = data
	}
	adversaryManifest, err := r.getAdversaryManifestReferrer(ctx, ref, manifestDigest)
	if err != nil {
		return PulledArtifact{}, err
	}
	return PulledArtifact{Reference: ref, Manifest: manifest, ManifestDigest: manifestDigest, AdversaryManifest: adversaryManifest, Blobs: blobs}, nil
}

func (r *HTTPRegistry) Resolve(ctx context.Context, ref Reference) (string, error) {
	_, digest, err := r.getManifest(ctx, ref)
	return digest, err
}

func (r *HTTPRegistry) pushBlob(ctx context.Context, ref Reference, blob Blob) error {
	head, err := r.newRequest(ctx, http.MethodHead, ref, "/blobs/"+blob.Descriptor.Digest, nil)
	if err != nil {
		return err
	}
	resp, err := r.do(head, ref, "repository:"+ref.Repository+":pull")
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK {
		_ = resp.Body.Close()
		return nil
	}
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusUnauthorized {
		defer resp.Body.Close()
		return registryError(resp)
	}
	_ = resp.Body.Close()

	start, err := r.newRequest(ctx, http.MethodPost, ref, "/blobs/uploads/", nil)
	if err != nil {
		return err
	}
	resp, err = r.do(start, ref, "repository:"+ref.Repository+":push,pull")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return registryError(resp)
	}
	location := resp.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("registry did not return upload location")
	}
	uploadURL := absoluteURL(r.scheme(), ref.Registry, location)
	separator := "?"
	if strings.Contains(uploadURL, "?") {
		separator = "&"
	}
	uploadURL += separator + "digest=" + blob.Descriptor.Digest
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, bytes.NewReader(blob.Data))
	if err != nil {
		return err
	}
	contentType := blob.Descriptor.MediaType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(blob.Data)))
	resp, err = r.do(req, ref, "repository:"+ref.Repository+":push,pull")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return registryError(resp)
	}
	return nil
}

func (r *HTTPRegistry) getManifest(ctx context.Context, ref Reference) ([]byte, string, error) {
	req, err := r.newRequest(ctx, http.MethodGet, ref, "/manifests/"+ref.ManifestReference(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", ImageManifestMediaType)
	resp, err := r.do(req, ref, "repository:"+ref.Repository+":pull")
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", registryError(resp)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		digest = Digest(data)
	}
	if err := VerifyDigest(data, digest); err != nil {
		return nil, "", err
	}
	return data, digest, nil
}

func (r *HTTPRegistry) getArtifactManifest(ctx context.Context, ref Reference, digest string) ([]byte, string, error) {
	req, err := r.newRequest(ctx, http.MethodGet, ref, "/manifests/"+digest, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", OCIArtifactManifestMediaType)
	resp, err := r.do(req, ref, "repository:"+ref.Repository+":pull")
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", registryError(resp)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	got := resp.Header.Get("Docker-Content-Digest")
	if got == "" {
		got = Digest(data)
	}
	if err := VerifyDigest(data, got); err != nil {
		return nil, "", err
	}
	return data, got, nil
}

func (r *HTTPRegistry) getAdversaryManifestReferrer(ctx context.Context, ref Reference, imageDigest string) ([]byte, error) {
	req, err := r.newRequest(ctx, http.MethodGet, ref, "/referrers/"+imageDigest+"?artifactType="+url.QueryEscape(AdversaryManifestMediaType), nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.do(req, ref, "repository:"+ref.Repository+":pull")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, registryError(resp)
	}
	var referrers ReferrersResponse
	if err := json.NewDecoder(resp.Body).Decode(&referrers); err != nil {
		return nil, err
	}
	for _, descriptor := range referrers.Manifests {
		if descriptor.ArtifactType != AdversaryManifestMediaType {
			continue
		}
		data, _, err := r.getArtifactManifest(ctx, ref, descriptor.Digest)
		if err != nil {
			return nil, err
		}
		var artifact ArtifactManifest
		if err := json.Unmarshal(data, &artifact); err != nil {
			return nil, err
		}
		if artifact.ArtifactType != AdversaryManifestMediaType || artifact.Subject.Digest != imageDigest || len(artifact.Blobs) != 1 {
			continue
		}
		return r.getBlob(ctx, ref, artifact.Blobs[0])
	}
	return nil, nil
}

func (r *HTTPRegistry) getBlob(ctx context.Context, ref Reference, descriptor Descriptor) ([]byte, error) {
	req, err := r.newRequest(ctx, http.MethodGet, ref, "/blobs/"+descriptor.Digest, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.do(req, ref, "repository:"+ref.Repository+":pull")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, registryError(resp)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != descriptor.Size {
		return nil, fmt.Errorf("blob %s size mismatch: got %d, want %d", descriptor.Digest, len(data), descriptor.Size)
	}
	if err := VerifyDigest(data, descriptor.Digest); err != nil {
		return nil, err
	}
	return data, nil
}

func (r *HTTPRegistry) newRequest(ctx context.Context, method string, ref Reference, suffix string, body io.Reader) (*http.Request, error) {
	u := fmt.Sprintf("%s://%s/v2/%s%s", r.scheme(), ref.Registry, ref.Repository, suffix)
	return http.NewRequestWithContext(ctx, method, u, body)
}

func (r *HTTPRegistry) do(req *http.Request, ref Reference, scope string) (*http.Response, error) {
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	var creds Credentials
	var hasCreds bool
	if r.Credentials != nil {
		creds, hasCreds = r.Credentials.Credentials(ref.Registry)
		if hasCreds && req.Header.Get("Authorization") == "" && creds.Token == "" {
			ApplyAuthHeader(req, creds)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	challenge, ok := parseBearerChallenge(resp.Header.Get("WWW-Authenticate"))
	if !ok {
		r.debugf("oci auth: %s %s returned 401 without bearer challenge", req.Method, req.URL.Path)
		challenge, ok, err = r.rootBearerChallenge(req.Context(), client, ref)
		if err != nil {
			_ = resp.Body.Close()
			return nil, err
		}
		if !ok {
			challenge, ok = r.configuredBearerChallenge(ref)
		}
		if !ok {
			return resp, nil
		}
	}
	r.debugf("oci auth: %s %s challenge realm=%s service=%s scope=%s requested_scope=%s", req.Method, req.URL.Path, challenge.Realm, challenge.Service, challenge.Scope, scope)
	_ = resp.Body.Close()
	token, err := readBearerToken(client, challenge, scope, creds, hasCreds)
	if err != nil {
		return nil, err
	}
	retry := req.Clone(req.Context())
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		retry.Body = body
	}
	retry.Header.Set("Authorization", "Bearer "+token)
	r.debugf("oci auth: retrying %s %s authorization_header=%t", retry.Method, retry.URL.Path, retry.Header.Get("Authorization") != "")
	return client.Do(retry)
}

func (r *HTTPRegistry) rootBearerChallenge(ctx context.Context, client *http.Client, ref Reference) (bearerChallenge, bool, error) {
	u := fmt.Sprintf("%s://%s/v2/", r.scheme(), ref.Registry)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return bearerChallenge{}, false, err
	}
	r.debugf("oci auth: probing %s for bearer challenge", req.URL.Path)
	resp, err := client.Do(req)
	if err != nil {
		return bearerChallenge{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		r.debugf("oci auth: challenge probe returned %s", resp.Status)
		return bearerChallenge{}, false, nil
	}
	challenge, ok := parseBearerChallenge(resp.Header.Get("WWW-Authenticate"))
	if !ok {
		r.debugf("oci auth: challenge probe returned 401 without bearer challenge")
		return bearerChallenge{}, false, nil
	}
	return challenge, true, nil
}

func (r *HTTPRegistry) configuredBearerChallenge(ref Reference) (bearerChallenge, bool) {
	if r.BearerRealm == "" || r.BearerService == "" || r.BearerService != ref.Registry {
		return bearerChallenge{}, false
	}
	r.debugf("oci auth: using configured bearer challenge realm=%s service=%s", r.BearerRealm, r.BearerService)
	return bearerChallenge{Realm: r.BearerRealm, Service: r.BearerService}, true
}

func (r *HTTPRegistry) debugf(format string, args ...any) {
	if r.Debug == nil {
		return
	}
	fmt.Fprintf(r.Debug, format+"\n", args...)
}

func (r *HTTPRegistry) scheme() string {
	if r.PlainHTTP {
		return "http"
	}
	return "https"
}

func absoluteURL(scheme, registry, location string) string {
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		return location
	}
	if strings.HasPrefix(location, "/") {
		return scheme + "://" + registry + location
	}
	return scheme + "://" + registry + "/" + location
}

func registryError(resp *http.Response) error {
	data, _ := io.ReadAll(resp.Body)
	text := strings.TrimSpace(string(data))
	if text == "" {
		text = resp.Status
	}
	return fmt.Errorf("registry request failed: %s: %s", resp.Status, text)
}
