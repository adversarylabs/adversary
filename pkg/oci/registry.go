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
	// TokenAuthorities binds a registry to the only cross-origin bearer realm
	// and service allowed to receive its stored credentials.
	TokenAuthorities map[string]TokenAuthority
}

type TokenAuthority struct{ Origin, Service string }

type IngestionLimits struct {
	ManifestBytes       int64
	ConfigBytes         int64
	CompressedBlobBytes int64
}

var DefaultIngestionLimits = IngestionLimits{ManifestBytes: 4 << 20, ConfigBytes: 1 << 20, CompressedBlobBytes: 256 << 20}

func NewHTTPRegistry() *HTTPRegistry {
	return &HTTPRegistry{
		Client:      NewHTTPClient(),
		Credentials: DockerCredentialStore{},
		TokenAuthorities: map[string]TokenAuthority{
			"registry-1.docker.io": {Origin: "https://auth.docker.io", Service: "registry.docker.io"},
		},
	}
}

func (r *HTTPRegistry) Push(ctx context.Context, ref Reference, manifest []byte, blobs []Blob) (string, error) {
	ctx, cancel := withOperationDeadline(ctx)
	defer cancel()
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
	ctx, cancel := withOperationDeadline(ctx)
	defer cancel()
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
		if got != digest {
			return "", fmt.Errorf("registry manifest digest %s does not match uploaded content %s", got, digest)
		}
	}
	return digest, nil
}

func (r *HTTPRegistry) Pull(ctx context.Context, ref Reference) (PulledArtifact, error) {
	ctx, cancel := withOperationDeadline(ctx)
	defer cancel()
	manifestData, manifestDigest, err := r.getManifest(ctx, ref)
	if err != nil {
		return PulledArtifact{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return PulledArtifact{}, err
	}
	if manifest.MediaType != "" && manifest.MediaType != ImageManifestMediaType && manifest.MediaType != DockerImageManifestMediaType {
		return PulledArtifact{}, fmt.Errorf("unsupported manifest media type %s", manifest.MediaType)
	}
	if err := validatePulledManifest(manifest); err != nil {
		return PulledArtifact{}, err
	}
	pinned := ref
	pinned.Tag = ""
	pinned.Digest = manifestDigest
	blobs := map[string][]byte{}
	descriptors := append([]Descriptor{manifest.Config}, manifest.Layers...)
	for _, descriptor := range descriptors {
		data, err := r.getBlob(ctx, pinned, descriptor)
		if err != nil {
			return PulledArtifact{}, err
		}
		blobs[descriptor.Digest] = data
	}
	adversaryManifest, err := r.getAdversaryManifestReferrer(ctx, pinned, manifestDigest)
	if err != nil {
		return PulledArtifact{}, err
	}
	return PulledArtifact{Reference: ref, RawManifest: append([]byte(nil), manifestData...), Manifest: manifest, ManifestDigest: manifestDigest, AdversaryManifest: adversaryManifest, Blobs: blobs}, nil
}

func validatePulledManifest(manifest Manifest) error {
	if manifest.SchemaVersion != 2 || manifest.ArtifactType != ArtifactMediaType {
		return fmt.Errorf("manifest is not an adversary artifact")
	}
	if manifest.Config.MediaType != EmptyConfigMediaType || len(manifest.Layers) != 1 || manifest.Layers[0].MediaType != PackageLayerMediaType {
		return fmt.Errorf("unsupported adversary artifact config/layer layout")
	}
	return nil
}

func (r *HTTPRegistry) Resolve(ctx context.Context, ref Reference) (string, error) {
	ctx, cancel := withOperationDeadline(ctx)
	defer cancel()
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
	uploadURL, err := validatedLocation(r.scheme(), ref.Registry, location)
	if err != nil {
		return err
	}
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
	req.Header.Set("Accept", ImageManifestMediaType+", "+DockerImageManifestMediaType)
	resp, err := r.do(req, ref, "repository:"+ref.Repository+":pull")
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", registryError(resp)
	}
	data, err := readLimited(resp.Body, DefaultIngestionLimits.ManifestBytes, "manifest")
	if err != nil {
		return nil, "", err
	}
	actual := Digest(data)
	header := resp.Header.Get("Docker-Content-Digest")
	digest := header
	if ref.Digest != "" {
		digest = ref.Digest
	}
	if digest == "" {
		digest = actual
	}
	if header != "" && header != actual {
		return nil, "", fmt.Errorf("manifest digest header %s does not match content %s", header, actual)
	}
	if ref.Digest != "" && actual != ref.Digest {
		return nil, "", fmt.Errorf("requested manifest digest %s does not match content %s", ref.Digest, actual)
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
	data, err := readLimited(resp.Body, DefaultIngestionLimits.ManifestBytes, "artifact manifest")
	if err != nil {
		return nil, "", err
	}
	actual := Digest(data)
	header := resp.Header.Get("Docker-Content-Digest")
	if header != "" && header != digest {
		return nil, "", fmt.Errorf("artifact manifest digest header %s does not match requested %s", header, digest)
	}
	if actual != digest {
		return nil, "", fmt.Errorf("requested artifact manifest digest %s does not match content %s", digest, actual)
	}
	if err := VerifyDigest(data, digest); err != nil {
		return nil, "", err
	}
	return data, digest, nil
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
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return r.getAdversaryManifestFallback(ctx, ref, imageDigest)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, registryError(resp)
	}
	// Do not traverse registry-provided pagination links. The deterministic
	// digest-derived fallback avoids accepting another authority or ordering.
	if strings.TrimSpace(resp.Header.Get("Link")) != "" {
		return r.getAdversaryManifestFallback(ctx, ref, imageDigest)
	}
	data, err := readLimited(resp.Body, DefaultIngestionLimits.ManifestBytes, "referrers response")
	if err != nil {
		return nil, err
	}
	var referrers ReferrersResponse
	if err := json.Unmarshal(data, &referrers); err != nil {
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
		if artifact.MediaType != OCIArtifactManifestMediaType || artifact.ArtifactType != AdversaryManifestMediaType || !isImageManifestMediaType(artifact.Subject.MediaType) || artifact.Subject.Digest != imageDigest || len(artifact.Blobs) != 1 || artifact.Blobs[0].MediaType != AdversaryManifestMediaType {
			continue
		}
		return r.getBlob(ctx, ref, artifact.Blobs[0])
	}
	return r.getAdversaryManifestFallback(ctx, ref, imageDigest)
}

func (r *HTTPRegistry) getAdversaryManifestFallback(ctx context.Context, ref Reference, imageDigest string) ([]byte, error) {
	tag, err := AdversaryManifestArtifactTag(imageDigest)
	if err != nil {
		return nil, err
	}
	req, err := r.newRequest(ctx, http.MethodGet, ref, "/manifests/"+tag, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", OCIArtifactManifestMediaType)
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
	data, err := readLimited(resp.Body, DefaultIngestionLimits.ManifestBytes, "artifact manifest")
	if err != nil {
		return nil, err
	}
	actual := Digest(data)
	if header := resp.Header.Get("Docker-Content-Digest"); header != "" && header != actual {
		return nil, fmt.Errorf("artifact manifest digest header %s does not match content %s", header, actual)
	}
	var artifact ArtifactManifest
	if err := json.Unmarshal(data, &artifact); err != nil {
		return nil, err
	}
	if artifact.MediaType != OCIArtifactManifestMediaType || artifact.ArtifactType != AdversaryManifestMediaType || artifact.Subject.Digest != imageDigest || !isImageManifestMediaType(artifact.Subject.MediaType) || len(artifact.Blobs) != 1 || artifact.Blobs[0].MediaType != AdversaryManifestMediaType {
		return nil, fmt.Errorf("invalid adversary manifest fallback artifact")
	}
	return r.getBlob(ctx, ref, artifact.Blobs[0])
}

func isImageManifestMediaType(value string) bool {
	return value == ImageManifestMediaType || value == DockerImageManifestMediaType
}

func (r *HTTPRegistry) getBlob(ctx context.Context, ref Reference, descriptor Descriptor) ([]byte, error) {
	limit := DefaultIngestionLimits.CompressedBlobBytes
	switch descriptor.MediaType {
	case EmptyConfigMediaType, AdversaryManifestMediaType:
		limit = DefaultIngestionLimits.ConfigBytes
	case PackageLayerMediaType:
	default:
		return nil, fmt.Errorf("unsupported blob media type %q", descriptor.MediaType)
	}
	if descriptor.Size < 0 || descriptor.Size > limit {
		return nil, fmt.Errorf("blob %s exceeds %d byte limit", descriptor.Digest, limit)
	}
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
	data, err := readLimited(resp.Body, limit, "blob")
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

func readLimited(r io.Reader, limit int64, label string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d byte limit", label, limit)
	}
	return data, nil
}

func (r *HTTPRegistry) newRequest(ctx context.Context, method string, ref Reference, suffix string, body io.Reader) (*http.Request, error) {
	if r.PlainHTTP && !isLoopbackHost(ref.Registry) {
		return nil, fmt.Errorf("plain HTTP registry is restricted to loopback hosts")
	}
	u := fmt.Sprintf("%s://%s/v2/%s%s", r.scheme(), ref.Registry, ref.Repository, suffix)
	return http.NewRequestWithContext(ctx, method, u, body)
}

func (r *HTTPRegistry) do(req *http.Request, ref Reference, scope string) (*http.Response, error) {
	client := r.Client
	if client == nil {
		client = NewHTTPClient()
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
	if !validRepositoryScope(ref, scope) {
		return nil, fmt.Errorf("refusing bearer scope outside challenged repository")
	}
	sendCreds := hasCreds && r.trustedTokenAuthority(ref, challenge)
	if hasCreds && !sendCreds {
		r.debugf("oci auth: requesting anonymous token from untrusted cross-origin realm")
	}
	token, err := readBearerToken(req.Context(), client, challenge, scope, creds, sendCreds)
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

func validRepositoryScope(ref Reference, scope string) bool {
	prefix := "repository:" + ref.Repository + ":"
	if !strings.HasPrefix(scope, prefix) {
		return false
	}
	actions := strings.Split(strings.TrimPrefix(scope, prefix), ",")
	if len(actions) == 0 {
		return false
	}
	for _, action := range actions {
		if action != "pull" && action != "push" {
			return false
		}
	}
	return true
}

func (r *HTTPRegistry) trustedTokenAuthority(ref Reference, challenge bearerChallenge) bool {
	u, err := url.Parse(challenge.Realm)
	if err != nil {
		return false
	}
	registryService := challenge.Service == "" || challenge.Service == ref.Registry
	if sameOrigin(r.scheme(), ref.Registry, u.Scheme, u.Host) && registryService {
		return true
	}
	authority, ok := r.TokenAuthorities[ref.Registry]
	if !ok || authority.Service == "" || challenge.Service != authority.Service {
		return false
	}
	origin := u.Scheme + "://" + u.Host
	return strings.EqualFold(strings.TrimRight(authority.Origin, "/"), origin)
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

func validatedLocation(scheme, registry, location string) (string, error) {
	base, _ := url.Parse(scheme + "://" + registry + "/")
	u, err := url.Parse(strings.TrimSpace(location))
	if err != nil || u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("registry returned invalid upload location")
	}
	u = base.ResolveReference(u)
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Host)) {
		return "", fmt.Errorf("registry returned insecure upload location")
	}
	if !sameOrigin(scheme, registry, u.Scheme, u.Host) {
		return "", fmt.Errorf("registry returned cross-origin upload location")
	}
	return u.String(), nil
}

func registryError(resp *http.Response) error {
	data, _ := readLimited(resp.Body, 64<<10, "registry error response")
	text := sanitizeErrorText(string(data))
	var envelope struct {
		Errors []struct {
			Code, Message string
			Detail        json.RawMessage
		} `json:"errors"`
	}
	var codes []RegistryErrorCode
	if json.Unmarshal(data, &envelope) == nil {
		parts := make([]string, 0, len(envelope.Errors))
		for _, item := range envelope.Errors {
			code := sanitizeErrorText(item.Code)
			message := sanitizeErrorText(item.Message)
			detail := sanitizeErrorText(string(item.Detail))
			codes = append(codes, RegistryErrorCode{Code: code, Message: message, Detail: detail})
			parts = append(parts, strings.TrimSpace(code+": "+message))
		}
		if len(parts) > 0 {
			text = strings.Join(parts, "; ")
		}
	}
	if text == "" {
		text = resp.Status
	}
	registry, repository, operation := "", "", "request"
	if resp.Request != nil && resp.Request.URL != nil {
		registry, operation = resp.Request.URL.Host, strings.ToLower(resp.Request.Method)
		parts := strings.Split(strings.TrimPrefix(resp.Request.URL.Path, "/v2/"), "/")
		for i, part := range parts {
			if part == "manifests" || part == "blobs" || part == "referrers" {
				repository = strings.Join(parts[:i], "/")
				break
			}
		}
	}
	return &RegistryError{Operation: operation, Registry: registry, Repository: repository, StatusCode: resp.StatusCode, Status: resp.Status, Detail: text, Codes: codes}
}

func sanitizeErrorText(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 0x20 && r != 0x7f {
			return r
		}
		return ' '
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 1024 {
		value = value[:1024] + "…"
	}
	return value
}
