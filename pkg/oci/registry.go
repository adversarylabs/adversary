package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	Client      *http.Client
	Credentials CredentialStore
	PlainHTTP   bool
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
	digest := Digest(manifest)
	req, err := r.newRequest(ctx, http.MethodPut, ref, "/manifests/"+ref.ManifestReference(), bytes.NewReader(manifest))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", ImageManifestMediaType)
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
	return PulledArtifact{Reference: ref, Manifest: manifest, ManifestDigest: manifestDigest, Blobs: blobs}, nil
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
	req.Header.Set("Content-Type", "application/octet-stream")
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
		if hasCreds && req.Header.Get("Authorization") == "" {
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
		return resp, nil
	}
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
	return client.Do(retry)
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
