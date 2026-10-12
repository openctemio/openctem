package githubapp

// Check runs, pull requests and issue comments with an installation token.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// CheckAnnotation is one line-level note of a check run.
type CheckAnnotation struct {
	Path            string `json:"path"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`
	AnnotationLevel string `json:"annotation_level"` // notice, warning, failure
	Title           string `json:"title,omitempty"`
	Message         string `json:"message"`
}

// CheckRun is a completed check run to create.
type CheckRun struct {
	Name        string
	HeadSHA     string
	Conclusion  string // success, failure, neutral
	DetailsURL  string
	ExternalID  string
	Title       string
	Summary     string
	Annotations []CheckAnnotation
}

// PullRequest is the part of a pull request the decoration reads.
type PullRequest struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	Merged bool   `json:"merged"`
	// MergedAt is set on merged pull requests (the list endpoints report it,
	// not Merged).
	MergedAt *string `json:"merged_at"`
	Base     struct {
		Ref string `json:"ref"`
	} `json:"base"`
	MergeCommitSHA string `json:"merge_commit_sha"`
	Head           struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

// IssueComment is a pull request conversation comment.
type IssueComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
	User struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"user"`
}

func repoPath(owner, repo string) string {
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)
}

// installationDo sends a request with the installation's token.
func (a *App) installationDo(ctx context.Context, installationID int64, method, path string, body, out any) error {
	tok, err := a.InstallationToken(ctx, installationID)
	if err != nil {
		return err
	}
	return a.do(ctx, method, a.cfg.APIURL+path, "Bearer "+tok, body, out)
}

// CreateCheckRun posts a completed check run (annotations capped at 50, the
// API's limit per request).
func (a *App) CreateCheckRun(ctx context.Context, installationID int64, owner, repo string, c CheckRun) error {
	if len(c.Annotations) > 50 {
		c.Annotations = c.Annotations[:50]
	}
	body := map[string]any{
		"name": c.Name, "head_sha": c.HeadSHA, "status": "completed", "conclusion": c.Conclusion,
		"details_url": c.DetailsURL, "external_id": c.ExternalID,
		"output": map[string]any{"title": c.Title, "summary": c.Summary, "annotations": c.Annotations},
	}
	return a.installationDo(ctx, installationID, http.MethodPost, repoPath(owner, repo)+"/check-runs", body, nil)
}

// GetPullRequest reads a pull request.
func (a *App) GetPullRequest(ctx context.Context, installationID int64, owner, repo string, number int) (*PullRequest, error) {
	var pr PullRequest
	if err := a.installationDo(ctx, installationID, http.MethodGet,
		repoPath(owner, repo)+"/pulls/"+strconv.Itoa(number), nil, &pr); err != nil {
		return nil, err
	}
	return &pr, nil
}

// PullRequestsForCommit lists the pull requests a commit belongs to.
func (a *App) PullRequestsForCommit(ctx context.Context, installationID int64, owner, repo, sha string) ([]PullRequest, error) {
	var prs []PullRequest
	if err := a.installationDo(ctx, installationID, http.MethodGet,
		repoPath(owner, repo)+"/commits/"+url.PathEscape(sha)+"/pulls?per_page=10", nil, &prs); err != nil {
		return nil, err
	}
	return prs, nil
}

// FindIssueComment returns the app's own comment on a pull request that
// contains marker, or nil (first 500 comments).
func (a *App) FindIssueComment(ctx context.Context, installationID int64, owner, repo string, number int, marker string) (*IssueComment, error) {
	botLogin := a.cfg.Slug + "[bot]"
	for page := 1; page <= 5; page++ {
		var list []IssueComment
		path := fmt.Sprintf("%s/issues/%d/comments?per_page=100&page=%d", repoPath(owner, repo), number, page)
		if err := a.installationDo(ctx, installationID, http.MethodGet, path, nil, &list); err != nil {
			return nil, err
		}
		for i := range list {
			c := list[i]
			if c.User.Type == "Bot" && c.User.Login == botLogin && containsMarker(c.Body, marker) {
				return &c, nil
			}
		}
		if len(list) < 100 {
			break
		}
	}
	return nil, nil
}

func containsMarker(body, marker string) bool {
	return marker != "" && strings.Contains(body, marker)
}

// UpsertIssueComment updates the app's marked comment or creates one.
func (a *App) UpsertIssueComment(ctx context.Context, installationID int64, owner, repo string, number int, marker, body string) error {
	existing, err := a.FindIssueComment(ctx, installationID, owner, repo, number, marker)
	if err != nil {
		return err
	}
	if existing != nil {
		return a.installationDo(ctx, installationID, http.MethodPatch,
			fmt.Sprintf("%s/issues/comments/%d", repoPath(owner, repo), existing.ID), map[string]string{"body": body}, nil)
	}
	return a.installationDo(ctx, installationID, http.MethodPost,
		fmt.Sprintf("%s/issues/%d/comments", repoPath(owner, repo), number), map[string]string{"body": body}, nil)
}
