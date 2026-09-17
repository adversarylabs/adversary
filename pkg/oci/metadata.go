package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
		for start := 0; start < len(group); start += 16 {
			chunk := group[start:min(start+16, len(group))]
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
			for _, ref := range chunk {
				if _, ok := out[ref.Locator()]; ok {
					continue
				}
				item := Metadata{Ref: ref.Locator()}
				digest, e := r.Resolve(ctx, ref)
				if e == nil {
					item.Digest = digest
					var data []byte
					data, _, e = r.getAdversaryManifestReferrer(ctx, ref, digest)
					item.Manifest = string(data)
					if e == nil && len(data) == 0 {
						e = fmt.Errorf("manifest metadata unavailable")
					}
				}
				if e != nil {
					item.Error = e.Error()
				}
				out[ref.Locator()] = item
			}
		}
	}
	return out
}
