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

// decorationPermissions are what posting a check and a pull request comment
// needs; the token carries nothing more.
var decorationPermissions = map[string]string{"checks": "write", "pull_requests": "write", "metadata": "read"}

// installationDo sends a request about one repository with an installation
// token narrowed to that repository and to decorationPermissions.
func (a *App) installationDo(ctx context.Context, installationID int64, repo, method, path string, body, out any) error {
	return a.installationDoWith(ctx, installationID, repo, decorationPermissions, method, path, body, out)
}

// commitReadPermissions read a commit (its parents). An installation that
// was not granted contents read gets 422 from the token request, which the
// caller treats as "cannot tell".
var commitReadPermissions = map[string]string{"contents": "read", "metadata": "read"}

func (a *App) installationDoWith(ctx context.Context, installationID int64, repo string, perms map[string]string, method, path string, body, out any) error {
	tok, err := a.RepositoryToken(ctx, installationID, repo, perms)
	if err != nil {
		return err
	}
	return a.do(ctx, method, a.cfg.APIURL+path, "Bearer "+tok, body, out)
}

// CommitParents returns the parent commit ids of a commit.
func (a *App) CommitParents(ctx context.Context, installationID int64, owner, repo, sha string) ([]string, error) {
	var c struct {
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
	}
	if err := a.installationDoWith(ctx, installationID, repo, commitReadPermissions, http.MethodGet,
		repoPath(owner, repo)+"/commits/"+url.PathEscape(sha), nil, &c); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(c.Parents))
	for _, p := range c.Parents {
		out = append(out, p.SHA)
	}
	return out, nil
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
	return a.installationDo(ctx, installationID, repo, http.MethodPost, repoPath(owner, repo)+"/check-runs", body, nil)
}

// GetPullRequest reads a pull request.
func (a *App) GetPullRequest(ctx context.Context, installationID int64, owner, repo string, number int) (*PullRequest, error) {
	var pr PullRequest
	if err := a.installationDo(ctx, installationID, repo, http.MethodGet,
		repoPath(owner, repo)+"/pulls/"+strconv.Itoa(number), nil, &pr); err != nil {
		return nil, err
	}
	return &pr, nil
}

// PullRequestsForCommit lists the pull requests a commit belongs to.
func (a *App) PullRequestsForCommit(ctx context.Context, installationID int64, owner, repo, sha string) ([]PullRequest, error) {
	var prs []PullRequest
	if err := a.installationDo(ctx, installationID, repo, http.MethodGet,
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
		if err := a.installationDo(ctx, installationID, repo, http.MethodGet, path, nil, &list); err != nil {
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
		return a.installationDo(ctx, installationID, repo, http.MethodPatch,
			fmt.Sprintf("%s/issues/comments/%d", repoPath(owner, repo), existing.ID), map[string]string{"body": body}, nil)
	}
	return a.installationDo(ctx, installationID, repo, http.MethodPost,
		fmt.Sprintf("%s/issues/%d/comments", repoPath(owner, repo), number), map[string]string{"body": body}, nil)
}
