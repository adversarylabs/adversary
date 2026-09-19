package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const (
	metadataBatchSize           = 64
	metadataFallbackConcurrency = 8
)

type Metadata struct {
	Ref      string `json:"ref"`
	Digest   string `json:"digest,omitempty"`
	Manifest string `json:"manifest,omitempty"`
	Error    string `json:"error,omitempty"`
}

// MetadataBatch fetches only manifest metadata, never package layers. Results
// are keyed by exact locator. Older registries and private repositories fall
// back to authenticated OCI referrer discovery.
func (r *HTTPRegistry) MetadataBatch(ctx context.Context, refs []Reference) map[string]Metadata {
	ctx, cancel := withOperationDeadline(ctx)
	defer cancel()
	out := map[string]Metadata{}
	groups := map[string][]Reference{}
	for _, ref := range refs {
		groups[ref.Registry] = append(groups[ref.Registry], ref)
	}
	for _, group := range groups {
		for start := 0; start < len(group); start += metadataBatchSize {
			chunk := group[start:min(start+metadataBatchSize, len(group))]
			q := url.Values{}
			for _, ref := range chunk {
				q.Add("ref", ref.Repository+ref.Locator()[len(ref.Name()):])
			}
			req, err := r.newRequest(ctx, http.MethodGet, chunk[0], "", nil)
			if err == nil {
				req.URL.Path = "/v2/metadata"
				req.URL.RawQuery = q.Encode()
				// Public metadata needs no credentials; private entries use the usual
				// per-repository challenge flow below instead of broadening token scopes.
				client := r.Client
				if client == nil {
					client = NewHTTPClient()
				}
				resp, e := client.Do(req)
				if e == nil {
					if resp.StatusCode == http.StatusOK {
						data, e := readLimited(resp.Body, 8<<20, "metadata batch")
						var result struct {
							Items []Metadata `json:"items"`
						}
						if e == nil && json.Unmarshal(data, &result) == nil {
							for _, item := range result.Items {
								for _, ref := range chunk {
									if item.Ref == ref.Repository+ref.Locator()[len(ref.Name()):] && item.Error == "" && item.Manifest != "" {
										if _, e := ParseDigest(item.Digest); e == nil && (ref.Digest == "" || ref.Digest == item.Digest) {
											out[ref.Locator()] = item
										}
									}
								}
							}
						}
					}
					resp.Body.Close()
				}
			}
			missing := make([]Reference, 0, len(chunk))
			for _, ref := range chunk {
				if _, ok := out[ref.Locator()]; !ok {
					missing = append(missing, ref)
				}
			}
			for key, item := range r.metadataFallbackBatch(ctx, missing) {
				out[key] = item
			}
		}
	}
	return out
}

func (r *HTTPRegistry) metadataFallbackBatch(ctx context.Context, refs []Reference) map[string]Metadata {
	out := make(map[string]Metadata, len(refs))
	if len(refs) == 0 {
		return out
	}
	type result struct {
		key  string
		item Metadata
	}
	jobs := make(chan Reference, len(refs))
	results := make(chan result, len(refs))
	for _, ref := range refs {
		jobs <- ref
	}
	close(jobs)
	workers := min(metadataFallbackConcurrency, len(refs))
	for range workers {
		go func() {
			for ref := range jobs {
				item := Metadata{Ref: ref.Locator()}
				digest, err := r.Resolve(ctx, ref)
				if err == nil {
					item.Digest = digest
					var data []byte
					data, _, err = r.getAdversaryManifestReferrer(ctx, ref, digest)
					item.Manifest = string(data)
					if err == nil && len(data) == 0 {
						err = fmt.Errorf("manifest metadata unavailable")
					}
				}
				if err != nil {
					item.Error = err.Error()
				}
				results <- result{key: ref.Locator(), item: item}
			}
		}()
	}
	for range refs {
		completed := <-results
		out[completed.key] = completed.item
	}
	return out
}
