package githubreview

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/adversarylabs/adversary/internal/application"
)

var reviewMarkerPattern = regexp.MustCompile(`<!--\s+adversary-review:v[12]\s+([\s\S]*?)-->`)

type reviewFindingKey struct {
	adversary string
	finding   string
}

func resolveAddressedThreads(ctx context.Context, plan CommentPlan, opts PostOptions) (int, error) {
	reviewed := make(map[string]bool, len(plan.ReviewedAdversaries))
	for _, adversary := range plan.ReviewedAdversaries {
		reviewed[sanitizeMarker(adversary)] = true
	}
	if len(reviewed) == 0 {
		return 0, nil
	}

	current := make(map[reviewFindingKey]bool, len(plan.Comments)+len(plan.Skipped))
	for _, comment := range plan.Comments {
		current[reviewFindingKey{sanitizeMarker(comment.Adversary), sanitizeMarker(comment.FindingID)}] = true
	}
	for _, finding := range plan.Skipped {
		current[reviewFindingKey{sanitizeMarker(finding.Adversary), sanitizeMarker(finding.FindingID)}] = true
	}

	threads, err := listOwnedReviewThreads(ctx, opts)
	if err != nil {
		return 0, mapGitHubErr("list review threads", err)
	}
	resolved := 0
	for _, thread := range threads {
		key, ok := reviewMarkerKey(thread.body)
		if !ok || !reviewed[key.adversary] || current[key] {
			continue
		}
		var mutation struct {
			ResolveReviewThread struct {
				Thread struct {
					IsResolved bool `json:"isResolved"`
				} `json:"thread"`
			} `json:"resolveReviewThread"`
		}
		err := opts.Client.GraphQL(ctx, `
mutation($threadId:ID!){
  resolveReviewThread(input:{threadId:$threadId}){ thread{ isResolved } }
}`, map[string]any{"threadId": thread.id}, &mutation)
		if err != nil {
			return resolved, mapGitHubErr("resolve review thread", err)
		}
		if !mutation.ResolveReviewThread.Thread.IsResolved {
			return resolved, &application.Error{
				Operation: "resolve review thread",
				Kind:      "network",
				Err:       fmt.Errorf("GitHub did not resolve thread %s", thread.id),
			}
		}
		resolved++
	}
	return resolved, nil
}

type ownedReviewThread struct {
	id   string
	body string
}

func listOwnedReviewThreads(ctx context.Context, opts PostOptions) ([]ownedReviewThread, error) {
	var result []ownedReviewThread
	var after any
	for page := 0; page < 20; page++ {
		var response struct {
			Viewer struct {
				Login string `json:"login"`
			} `json:"viewer"`
			Repository struct {
				PullRequest struct {
					ReviewThreads struct {
						Nodes []struct {
							ID         string `json:"id"`
							IsResolved bool   `json:"isResolved"`
							Comments   struct {
								Nodes []struct {
									Body   string `json:"body"`
									Author *struct {
										Login string `json:"login"`
									} `json:"author"`
								} `json:"nodes"`
							} `json:"comments"`
						} `json:"nodes"`
						PageInfo struct {
							HasNextPage bool   `json:"hasNextPage"`
							EndCursor   string `json:"endCursor"`
						} `json:"pageInfo"`
					} `json:"reviewThreads"`
				} `json:"pullRequest"`
			} `json:"repository"`
		}
		err := opts.Client.GraphQL(ctx, `
query($owner:String!,$name:String!,$number:Int!,$after:String){
  viewer{ login }
  repository(owner:$owner,name:$name){
    pullRequest(number:$number){
      reviewThreads(first:100,after:$after){
        nodes{ id isResolved comments(first:1){ nodes{ body author{ login } } } }
        pageInfo{ hasNextPage endCursor }
      }
    }
  }
}`, map[string]any{
			"owner": opts.Owner, "name": opts.Repo, "number": opts.Number, "after": after,
		}, &response)
		if err != nil {
			return nil, err
		}
		viewer := strings.ToLower(response.Viewer.Login)
		threads := response.Repository.PullRequest.ReviewThreads
		for _, thread := range threads.Nodes {
			if thread.IsResolved || len(thread.Comments.Nodes) == 0 {
				continue
			}
			root := thread.Comments.Nodes[0]
			if root.Author == nil || strings.ToLower(root.Author.Login) != viewer {
				continue
			}
			result = append(result, ownedReviewThread{id: thread.ID, body: root.Body})
		}
		if !threads.PageInfo.HasNextPage {
			return result, nil
		}
		if threads.PageInfo.EndCursor == "" {
			return nil, fmt.Errorf("GitHub review thread pagination returned an empty cursor")
		}
		after = threads.PageInfo.EndCursor
	}
	return nil, fmt.Errorf("GitHub review thread pagination exceeded 2000 threads")
}

func reviewMarkerKey(body string) (reviewFindingKey, bool) {
	match := reviewMarkerPattern.FindStringSubmatch(body)
	if len(match) != 2 {
		return reviewFindingKey{}, false
	}
	adversary := markerValue(match[1], "adversary")
	finding := markerValue(match[1], "finding")
	if adversary == "" || finding == "" {
		return reviewFindingKey{}, false
	}
	return reviewFindingKey{adversary: adversary, finding: finding}, true
}

func markerValue(marker, name string) string {
	for _, field := range strings.Fields(marker) {
		key, value, ok := strings.Cut(field, "=")
		if ok && key == name {
			return value
		}
	}
	return ""
}
