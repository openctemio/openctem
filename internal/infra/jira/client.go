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
	"strings"
	"time"

	"github.com/openctemio/api/pkg/httpsec"
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

	body := map[string]any{"fields": fields}
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

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("jira api error (status %d): %s", resp.StatusCode, string(respBody))
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
	if err := json.NewDecoder(resp.Body).Decode(&issue); err != nil {
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

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jira api error (status %d): %s", resp.StatusCode, string(respBody))
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
		return fmt.Errorf("jira transition error (status %d): %s", resp.StatusCode, string(respBody))
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
		return fmt.Errorf("jira comment error (status %d): %s", resp.StatusCode, string(respBody))
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
