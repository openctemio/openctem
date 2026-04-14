// Package jira provides a REST API client for Jira Cloud/Server.
package jira

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is a Jira REST API client.
type Client struct {
	baseURL    string
	email      string
	apiToken   string
	httpClient *http.Client
}

// NewClient creates a new Jira client.
// baseURL should be like "https://myorg.atlassian.net"
func NewClient(baseURL, email, apiToken string) *Client {
	return &Client{
		baseURL:  baseURL,
		email:    email,
		apiToken: apiToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
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
	ID      string `json:"id"`
	Key     string `json:"key"`      // e.g. "PROJ-123"
	SelfURL string `json:"self"`     // REST API URL
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

	respBody, err := io.ReadAll(resp.Body)
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
	url := fmt.Sprintf("%s/rest/api/2/issue/%s?fields=status", c.baseURL, issueKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
