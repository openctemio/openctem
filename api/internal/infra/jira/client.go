// Package jira provides a REST API client for Jira Cloud/Server.
package jira

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

const maxResponseSize = 10 * 1024 * 1024 // 10MB

// ErrNoMatchingTransition is returned by TransitionToStatus when the issue's
// workflow offers no transition that lands on the requested status. The caller
// should fall back to a comment rather than treat this as a hard failure.
var ErrNoMatchingTransition = errors.New("no jira transition to target status")

// Client is a Jira REST API client.
type Client struct {
	baseURL    string
	email      string
	apiToken   string
	httpClient *http.Client
}

// NewClient creates a new Jira client.
// baseURL should be like "https://myorg.atlassian.net"
func NewClient(baseURL, email, apiToken string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("invalid Jira URL: must use https")
	}
	// SSRF: delegate the blocklist to pkg/httpsec — the previous inline
	// prefix check missed CGNAT (100.64/10), 172.16/12, IPv6 link-local,
	// multicast, and DNS-resolved attacks. ValidateURL resolves the
	// hostname and rejects if any A/AAAA record falls in a blocked CIDR.
	if _, err := httpsec.ValidateURL(baseURL); err != nil {
		return nil, fmt.Errorf("invalid Jira URL: %w", err)
	}

	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		email:    email,
		apiToken: apiToken,
		// SSRF: SafeHTTPClient's dialer is the belt to ValidateURL's
		// braces — even if a redirect or DNS rebinding tries to pivot
		// to private space, the dial fails closed.
		httpClient: httpsec.SafeHTTPClient(30 * time.Second),
	}, nil
}

// CreateIssueInput contains fields for creating a Jira issue.
type CreateIssueInput struct {
	ProjectKey  string
	Summary     string
	Description string
	IssueType   string // "Bug", "Task", "Story"
	Priority    string // "Highest", "High", "Medium", "Low", "Lowest"
	Labels      []string
	// ParentKey makes the issue a child of this issue (an epic).
	ParentKey string
	// Marker, when set, is written into the create request itself (the
	// issue property MarkerProperty and the label MarkerLabel), so a retry
	// after a lost response finds the issue instead of creating another.
	Marker *IssueMarker
}

// MarkerProperty is the issue entity property that carries the marker.
const MarkerProperty = "openctem"

// IssueMarker names the OpenCTEM object an issue was created for: the
// object's id, its kind (task or finding) and the integration that created
// it. Stored as the issue property {"o":..,"k":..,"i":..}.
type IssueMarker struct {
	Object      string `json:"o"`
	Kind        string `json:"k"`
	Integration string `json:"i"`
}

// markerObjectRe is the shape of an object id in a marker (a UUID).
var markerObjectRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// MarkerLabel is the label that makes a marked issue searchable: issue
// properties are only searchable in JQL when an installed app indexes them,
// a label always is. The property, not the label, is what a lookup trusts.
func MarkerLabel(objectID string) string { return "openctem-ref-" + objectID }

// applyMarker adds the marker's property to the create body and its label to
// the fields that already carry labels.
func applyMarker(body, fields map[string]any, m *IssueMarker) {
	if m == nil || !markerObjectRe.MatchString(m.Object) {
		return
	}
	body["properties"] = []map[string]any{{"key": MarkerProperty, "value": m}}
	// The label goes only where labels are already sent: a project whose
	// create screen has no labels field refuses an issue that sets one.
	if _, ok := fields["labels"]; !ok {
		return
	}
	labels := []string{}
	switch v := fields["labels"].(type) {
	case []string:
		labels = append(labels, v...)
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				labels = append(labels, s)
			}
		}
	}
	fields["labels"] = append(labels, MarkerLabel(m.Object))
}

// MarkedIssue is an issue found by its marker, with the marker it carries.
type MarkedIssue struct {
	ID        string
	Key       string
	BrowseURL string
	Marker    IssueMarker
}

// FindIssuesByMarker lists the issues labeled for the marker's object
// (at most 10) with the marker property each one carries. The caller
// compares the property with the marker it expects: the label alone is
// never trusted.
func (c *Client) FindIssuesByMarker(ctx context.Context, objectID string) ([]MarkedIssue, error) {
	if !markerObjectRe.MatchString(objectID) {
		return nil, fmt.Errorf("invalid marker object id")
	}
	q := url.Values{}
	q.Set("jql", `labels = "`+MarkerLabel(objectID)+`" ORDER BY created ASC`)
	q.Set("fields", "summary")
	q.Set("properties", MarkerProperty)
	q.Set("maxResults", "10")
	var out struct {
		Issues []struct {
			ID         string                     `json:"id"`
			Key        string                     `json:"key"`
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"issues"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/rest/api/2/search?"+q.Encode(), nil, &out); err != nil {
		return nil, err
	}
	issues := make([]MarkedIssue, 0, len(out.Issues))
	for _, i := range out.Issues {
		mi := MarkedIssue{ID: i.ID, Key: i.Key, BrowseURL: c.baseURL + "/browse/" + i.Key}
		if raw, ok := i.Properties[MarkerProperty]; ok {
			_ = json.Unmarshal(raw, &mi.Marker)
		}
		issues = append(issues, mi)
	}
	return issues, nil
}

// CreateIssueResult contains the response from creating a Jira issue.
type CreateIssueResult struct {
	ID        string `json:"id"`
	Key       string `json:"key"`        // e.g. "PROJ-123"
	SelfURL   string `json:"self"`       // REST API URL
	BrowseURL string `json:"browse_url"` // Human-readable URL
}

// CreateIssue creates a new issue in Jira.
func (c *Client) CreateIssue(ctx context.Context, input CreateIssueInput) (*CreateIssueResult, error) {
	if input.IssueType == "" {
		input.IssueType = "Bug"
	}

	fields := map[string]any{
		"project":   map[string]string{"key": input.ProjectKey},
		"summary":   input.Summary,
		"issuetype": map[string]string{"name": input.IssueType},
	}

	if input.Description != "" {
		fields["description"] = input.Description
	}
	if input.Priority != "" {
		fields["priority"] = map[string]string{"name": input.Priority}
	}
	if len(input.Labels) > 0 {
		fields["labels"] = input.Labels
	}
	if input.ParentKey != "" {
		fields["parent"] = map[string]string{"key": input.ParentKey}
	}

	body := map[string]any{"fields": fields}
	applyMarker(body, fields, input.Marker)
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/rest/api/2/issue", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(c.email, c.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jira api call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := httpsec.ReadLimited(resp.Body, maxResponseSize)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, httpsec.NewUpstreamStatusError(ctx, "jira", resp.StatusCode, respBody)
	}

	var result CreateIssueResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	result.BrowseURL = c.baseURL + "/browse/" + result.Key
	return &result, nil
}

// GetIssueStatus fetches the current status of a Jira issue.
func (c *Client) GetIssueStatus(ctx context.Context, issueKey string) (string, error) {
	u := fmt.Sprintf("%s/rest/api/2/issue/%s?fields=status", c.baseURL, url.PathEscape(issueKey))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(c.email, c.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("jira api call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("jira api error (status %d)", resp.StatusCode)
	}

	var issue struct {
		Fields struct {
			Status struct {
				Name string `json:"name"`
			} `json:"status"`
		} `json:"fields"`
	}
	if err := httpsec.DecodeJSON(resp.Body, httpsec.MaxResponseBytes, &issue); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	return issue.Fields.Status.Name, nil
}

// Transition is an available Jira workflow transition for an issue.
type Transition struct {
	ID           string // transition id to POST (NOT the status name)
	Name         string // transition name, e.g. "Done"
	ToStatusName string // resulting status name, e.g. "Done"
}

// GetTransitions lists the workflow transitions currently available for an
// issue. Jira has no "set status" — you POST one of these transition IDs, and
// the available set depends on the issue's current status + project workflow.
// Callers resolve a desired status name to a transition via ToStatusName.
func (c *Client) GetTransitions(ctx context.Context, issueKey string) ([]Transition, error) {
	u := fmt.Sprintf("%s/rest/api/2/issue/%s/transitions", c.baseURL, url.PathEscape(issueKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(c.email, c.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jira api call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := httpsec.ReadLimited(resp.Body, maxResponseSize)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, httpsec.NewUpstreamStatusError(ctx, "jira", resp.StatusCode, respBody)
	}

	var parsed struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			To   struct {
				Name string `json:"name"`
			} `json:"to"`
		} `json:"transitions"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	out := make([]Transition, 0, len(parsed.Transitions))
	for _, t := range parsed.Transitions {
		out = append(out, Transition{ID: t.ID, Name: t.Name, ToStatusName: t.To.Name})
	}
	return out, nil
}

// DoTransition moves an issue through the given transition id. An optional
// comment is attached atomically with the transition (Jira's update.comment).
func (c *Client) DoTransition(ctx context.Context, issueKey, transitionID, comment string) error {
	body := map[string]any{
		"transition": map[string]string{"id": transitionID},
	}
	if comment != "" {
		body["update"] = map[string]any{
			"comment": []map[string]any{
				{"add": map[string]string{"body": comment}},
			},
		}
	}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	u := fmt.Sprintf("%s/rest/api/2/issue/%s/transitions", c.baseURL, url.PathEscape(issueKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(c.email, c.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("jira api call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Jira returns 204 No Content on a successful transition.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return fmt.Errorf("jira transition: %w", httpsec.NewUpstreamStatusError(ctx, "jira", resp.StatusCode, respBody))
	}
	return nil
}

// AddComment posts a comment on an issue. Used as the fall-back when the desired
// status has no available transition (workflow forbids the move) so the change
// is still visible to a human.
func (c *Client) AddComment(ctx context.Context, issueKey, body string) error {
	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	u := fmt.Sprintf("%s/rest/api/2/issue/%s/comment", c.baseURL, url.PathEscape(issueKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(c.email, c.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("jira api call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return fmt.Errorf("jira comment: %w", httpsec.NewUpstreamStatusError(ctx, "jira", resp.StatusCode, respBody))
	}
	return nil
}

// TransitionToStatus resolves a target status NAME to an available transition
// and performs it. Returns ErrNoMatchingTransition if the workflow offers no
// transition to that status, so the caller can fall back to AddComment. The
// match is case-insensitive on the resulting status name.
func (c *Client) TransitionToStatus(ctx context.Context, issueKey, targetStatus, comment string) error {
	transitions, err := c.GetTransitions(ctx, issueKey)
	if err != nil {
		return err
	}
	for _, t := range transitions {
		if strings.EqualFold(t.ToStatusName, targetStatus) {
			return c.DoTransition(ctx, issueKey, t.ID, comment)
		}
	}
	return ErrNoMatchingTransition
}

// Project is a Jira project as returned by the project-search endpoint.
type Project struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Name string `json:"name"`
}

// maxProjectPages bounds the project-search pagination so a very large or
// misbehaving instance can't make us loop unboundedly.
const maxProjectPages = 40

// ListProjects returns the projects visible to the configured credentials,
// for the admin project picker. It pages through Jira's project-search
// endpoint (50 per page) until isLast.
func (c *Client) ListProjects(ctx context.Context) ([]Project, error) {
	const pageSize = 50
	var projects []Project
	startAt := 0
	for page := 0; page < maxProjectPages; page++ {
		u := fmt.Sprintf("%s/rest/api/2/project/search?startAt=%d&maxResults=%d", c.baseURL, startAt, pageSize)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.SetBasicAuth(c.email, c.apiToken)
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("jira api call: %w", err)
		}
		body, err := httpsec.ReadLimited(resp.Body, maxResponseSize)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("jira api error (status %d)", resp.StatusCode)
		}

		var pageResp struct {
			Values []Project `json:"values"`
			IsLast bool      `json:"isLast"`
		}
		if err := json.Unmarshal(body, &pageResp); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		projects = append(projects, pageResp.Values...)
		if pageResp.IsLast || len(pageResp.Values) == 0 {
			break
		}
		startAt += len(pageResp.Values)
	}
	return projects, nil
}

// TestConnection verifies Jira credentials by fetching server info.
func (c *Client) TestConnection(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/rest/api/2/serverInfo", nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(c.email, c.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("jira connection failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jira authentication failed (status %d)", resp.StatusCode)
	}
	return nil
}

// SiteURL is the Jira site this client talks to (scheme and host).
func (c *Client) SiteURL() string { return c.baseURL }

// Issue is a Jira issue found by SearchIssues.
type Issue struct {
	Key       string
	Summary   string
	Type      string
	Status    string
	BrowseURL string
}

// issueKeyRe matches a Jira issue key such as SEC-42.
var issueKeyRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]+-\d+$`)

// SearchJQL builds the JQL for a picker query: an exact key when the text is
// one, else a text search; quotes and backslashes are escaped.
func SearchJQL(text string) string {
	text = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, text)
	if len(text) > 200 {
		text = text[:200]
	}
	text = strings.TrimSpace(text)
	if issueKeyRe.MatchString(strings.ToUpper(text)) {
		return `key = "` + strings.ToUpper(text) + `"`
	}
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(text)
	if esc == "" {
		return `ORDER BY updated DESC`
	}
	return `text ~ "` + esc + `" ORDER BY updated DESC`
}

// SearchIssues searches issues the credentials can see (at most max).
func (c *Client) SearchIssues(ctx context.Context, text string, max int) ([]Issue, error) {
	if max <= 0 || max > 50 {
		max = 20
	}
	q := url.Values{}
	q.Set("jql", SearchJQL(text))
	q.Set("fields", "summary,issuetype,status")
	q.Set("maxResults", strconv.Itoa(max))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/rest/api/2/search?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(c.email, c.apiToken)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jira api call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := httpsec.ReadLimited(resp.Body, maxResponseSize)
		return nil, httpsec.NewUpstreamStatusError(ctx, "jira", resp.StatusCode, body)
	}
	var out struct {
		Issues []struct {
			Key    string `json:"key"`
			Fields struct {
				Summary   string `json:"summary"`
				IssueType struct {
					Name string `json:"name"`
				} `json:"issuetype"`
				Status struct {
					Name string `json:"name"`
				} `json:"status"`
			} `json:"fields"`
		} `json:"issues"`
	}
	if err := httpsec.DecodeJSON(resp.Body, httpsec.MaxResponseBytes, &out); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	issues := make([]Issue, 0, len(out.Issues))
	for _, i := range out.Issues {
		issues = append(issues, Issue{
			Key: i.Key, Summary: i.Fields.Summary, Type: i.Fields.IssueType.Name,
			Status: i.Fields.Status.Name, BrowseURL: c.baseURL + "/browse/" + i.Key,
		})
	}
	return issues, nil
}
