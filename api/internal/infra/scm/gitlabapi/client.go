// Package gitlabapi talks to a GitLab instance with a group access token:
// token and group checks, commit statuses and merge request notes
// (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md).
//
// The token never appears in logs or errors: errors carry the HTTP status
// and GitLab's message only.
package gitlabapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// Client calls one GitLab host with one token.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New creates a client for host ("gitlab.com" or a self-managed host name;
// https only). httpClient nil uses the SSRF-guarded client.
func New(host, token string, httpClient *http.Client) (*Client, error) {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" || strings.ContainsAny(host, "/?#@ ") {
		return nil, fmt.Errorf("gitlab: invalid host")
	}
	base := "https://" + host
	if httpClient == nil {
		if _, err := httpsec.ValidateURL(base); err != nil {
			return nil, fmt.Errorf("gitlab: host not allowed: %w", err)
		}
		httpClient = httpsec.SafeHTTPClient(20 * time.Second)
	}
	c := *httpClient
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{base: base + "/api/v4", token: token, http: &c}, nil
}

// NewWithBase creates a client for a full API base URL (tests).
func NewWithBase(base, token string, httpClient *http.Client) *Client {
	return &Client{base: strings.TrimRight(base, "/"), token: token, http: httpClient}
}

// StatusError is a GitLab error response.
type StatusError struct {
	Status  int
	Message string
}

func (e *StatusError) Error() string { return fmt.Sprintf("gitlab: %d %s", e.Status, e.Message) }

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "openctem-ci")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("gitlab: %s request failed", method)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return fmt.Errorf("gitlab: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Message any    `json:"message"`
			Error   string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		msg := e.Error
		if s, ok := e.Message.(string); ok {
			msg = s
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return &StatusError{Status: resp.StatusCode, Message: msg}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// TokenInfo is what GitLab says about the token itself.
type TokenInfo struct {
	Active    bool     `json:"active"`
	Revoked   bool     `json:"revoked"`
	Scopes    []string `json:"scopes"`
	UserID    int64    `json:"user_id"`
	ExpiresAt string   `json:"expires_at"`
}

// Token reads the token's own record (personal, project or group token).
func (c *Client) Token(ctx context.Context) (*TokenInfo, error) {
	var t TokenInfo
	if err := c.do(ctx, http.MethodGet, "/personal_access_tokens/self", nil, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// User is the user a token acts as.
type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	// Bot: a project or group access token's own user (never a person).
	Bot bool `json:"bot"`
}

// CurrentUser reads the user the token acts as.
func (c *Client) CurrentUser(ctx context.Context) (*User, error) {
	var u User
	if err := c.do(ctx, http.MethodGet, "/user", nil, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// Group is a GitLab group.
type Group struct {
	ID       int64  `json:"id"`
	FullPath string `json:"full_path"`
}

// Group reads a group by path or id.
func (c *Client) Group(ctx context.Context, pathOrID string) (*Group, error) {
	var g Group
	if err := c.do(ctx, http.MethodGet, "/groups/"+url.PathEscape(pathOrID), nil, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

// GroupMember reads one member of a group (to prove the token's user belongs
// to it directly, as a group access token's bot does).
func (c *Client) GroupMember(ctx context.Context, groupID, userID int64) (bool, error) {
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("/groups/%d/members/%d", groupID, userID), nil, nil)
	var se *StatusError
	if errors.As(err, &se) && se.Status == http.StatusNotFound {
		return false, nil
	}
	return err == nil, err
}

// MergeRequest is the part of a merge request the decoration reads.
type MergeRequest struct {
	IID   int    `json:"iid"`
	SHA   string `json:"sha"`
	State string `json:"state"`
	// HeadPipeline is the merge request's latest pipeline. For a merged
	// results pipeline its SHA is the merge result's commit, not SHA.
	HeadPipeline *Pipeline `json:"head_pipeline"`
}

// Pipeline is a pipeline as a merge request names it.
type Pipeline struct {
	ID  int64  `json:"id"`
	SHA string `json:"sha"`
}

// MergeRequest reads a merge request of a project.
func (c *Client) MergeRequest(ctx context.Context, projectPath string, iid int) (*MergeRequest, error) {
	var mr MergeRequest
	if err := c.do(ctx, http.MethodGet, "/projects/"+url.PathEscape(projectPath)+"/merge_requests/"+strconv.Itoa(iid), nil, &mr); err != nil {
		return nil, err
	}
	return &mr, nil
}

// SetCommitStatus sets an external commit status (state: success, failed).
// A pipelineID above zero attaches it to that pipeline of the commit (a
// merged results pipeline, which the merge request shows).
func (c *Client) SetCommitStatus(ctx context.Context, projectPath, sha, state, name, targetURL, description string, pipelineID int64) error {
	if len(description) > 255 {
		description = description[:255]
	}
	body := map[string]any{"state": state, "name": name, "target_url": targetURL, "description": description}
	if pipelineID > 0 {
		body["pipeline_id"] = pipelineID
	}
	return c.do(ctx, http.MethodPost, "/projects/"+url.PathEscape(projectPath)+"/statuses/"+url.PathEscape(sha), body, nil)
}

type note struct {
	ID     int64  `json:"id"`
	Body   string `json:"body"`
	Author struct {
		ID int64 `json:"id"`
	} `json:"author"`
}

// UpsertMergeRequestNote updates the token user's note holding marker, or
// adds one (first 500 notes).
func (c *Client) UpsertMergeRequestNote(ctx context.Context, projectPath string, iid int, authorID int64, marker, body string) error {
	base := "/projects/" + url.PathEscape(projectPath) + "/merge_requests/" + strconv.Itoa(iid) + "/notes"
	for page := 1; page <= 5; page++ {
		var notes []note
		if err := c.do(ctx, http.MethodGet, fmt.Sprintf("%s?per_page=100&page=%d&sort=asc", base, page), nil, &notes); err != nil {
			return err
		}
		for _, n := range notes {
			if n.Author.ID == authorID && strings.Contains(n.Body, marker) {
				return c.do(ctx, http.MethodPut, base+"/"+strconv.FormatInt(n.ID, 10), map[string]string{"body": body}, nil)
			}
		}
		if len(notes) < 100 {
			break
		}
	}
	return c.do(ctx, http.MethodPost, base, map[string]string{"body": body}, nil)
}
