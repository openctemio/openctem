package jira

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// Field and workflow metadata for the mapping editor (create metadata,
// project statuses, resolutions, workflow transitions). Read-only calls with
// the integration's own credentials.

// maxMetaPages bounds every paginated metadata read.
const maxMetaPages = 20

// Retry-After handling: a 429 surfaces as RateLimitedError so callers can
// back off for the time the tracker asked.

// RateLimitedError reports a 429 with the delay the tracker asked for.
type RateLimitedError struct{ RetryAfter time.Duration }

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("jira rate limit: retry after %s", e.RetryAfter)
}

func retryAfter(h http.Header) time.Duration {
	if s := h.Get("Retry-After"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n >= 0 && n <= 3600 {
			return time.Duration(n) * time.Second
		}
	}
	return 30 * time.Second
}

// getJSON performs an authenticated GET (or POST with body) and decodes the
// response into out.
func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		rd = bytes.NewReader(b)
	}
	var req *http.Request
	var err error
	if rd != nil {
		req, err = http.NewRequestWithContext(ctx, method, c.baseURL+path, rd)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	}
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(c.email, c.apiToken)
	req.Header.Set("Accept", "application/json")
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("jira api call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := httpsec.ReadLimited(resp.Body, maxResponseSize)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return &RateLimitedError{RetryAfter: retryAfter(resp.Header)}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return httpsec.NewUpstreamStatusError(ctx, "jira", resp.StatusCode, respBody)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	return nil
}

// IssueTypeRef is an issue type of a project.
type IssueTypeRef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Subtask bool   `json:"subtask"`
}

// ListIssueTypes lists the issue types a project can create.
func (c *Client) ListIssueTypes(ctx context.Context, projectKey string) ([]IssueTypeRef, error) {
	var out []IssueTypeRef
	for page, startAt := 0, 0; page < maxMetaPages; page++ {
		var resp struct {
			Values     []IssueTypeRef `json:"values"`
			IssueTypes []IssueTypeRef `json:"issueTypes"`
			IsLast     *bool          `json:"isLast"`
			Total      int            `json:"total"`
		}
		path := fmt.Sprintf("/rest/api/2/issue/createmeta/%s/issuetypes?startAt=%d&maxResults=50", url.PathEscape(projectKey), startAt)
		if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
			return nil, err
		}
		vals := resp.Values
		if len(vals) == 0 {
			vals = resp.IssueTypes
		}
		out = append(out, vals...)
		startAt += len(vals)
		if len(vals) == 0 || (resp.IsLast != nil && *resp.IsLast) || (resp.Total > 0 && startAt >= resp.Total) {
			break
		}
	}
	return out, nil
}

type rawAllowed struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type rawField struct {
	FieldID         string                `json:"fieldId"`
	Key             string                `json:"key"`
	Name            string                `json:"name"`
	Required        bool                  `json:"required"`
	HasDefaultValue bool                  `json:"hasDefaultValue"`
	Schema          ticketmap.FieldSchema `json:"schema"`
	AllowedValues   []rawAllowed          `json:"allowedValues"`
}

// maxAllowedValues bounds a field's allowed values kept for the editor.
const maxAllowedValues = 500

func (f rawField) meta() ticketmap.FieldMeta {
	id := f.FieldID
	if id == "" {
		id = f.Key
	}
	m := ticketmap.FieldMeta{ID: id, Name: f.Name, Required: f.Required, HasDefault: f.HasDefaultValue, Schema: f.Schema}
	for i, a := range f.AllowedValues {
		if i >= maxAllowedValues {
			break
		}
		name := a.Name
		if name == "" {
			name = a.Value
		}
		m.AllowedValues = append(m.AllowedValues, ticketmap.AllowedValue{ID: a.ID, Name: name})
	}
	return m
}

// ListCreateFields lists the fields of a project's create screen for one
// issue type, with schema, required flag and allowed values.
func (c *Client) ListCreateFields(ctx context.Context, projectKey, issueTypeID string) ([]ticketmap.FieldMeta, error) {
	var out []ticketmap.FieldMeta
	for page, startAt := 0, 0; page < maxMetaPages; page++ {
		var resp struct {
			Values []rawField `json:"values"`
			Fields []rawField `json:"fields"`
			IsLast *bool      `json:"isLast"`
			Total  int        `json:"total"`
		}
		path := fmt.Sprintf("/rest/api/2/issue/createmeta/%s/issuetypes/%s?startAt=%d&maxResults=50",
			url.PathEscape(projectKey), url.PathEscape(issueTypeID), startAt)
		if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
			return nil, err
		}
		vals := resp.Values
		if len(vals) == 0 {
			vals = resp.Fields
		}
		for _, f := range vals {
			out = append(out, f.meta())
		}
		startAt += len(vals)
		if len(vals) == 0 || (resp.IsLast != nil && *resp.IsLast) || (resp.Total > 0 && startAt >= resp.Total) {
			break
		}
	}
	return out, nil
}

// ListProjectStatuses lists the workflow statuses of one issue type of a
// project, with their categories.
func (c *Client) ListProjectStatuses(ctx context.Context, projectKey, issueTypeID string) ([]ticketmap.WorkflowStatus, error) {
	var resp []struct {
		ID       string `json:"id"`
		Statuses []struct {
			ID             string `json:"id"`
			Name           string `json:"name"`
			StatusCategory struct {
				Key string `json:"key"`
			} `json:"statusCategory"`
		} `json:"statuses"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/rest/api/2/project/"+url.PathEscape(projectKey)+"/statuses", nil, &resp); err != nil {
		return nil, err
	}
	var out []ticketmap.WorkflowStatus
	for _, it := range resp {
		if it.ID != issueTypeID {
			continue
		}
		for _, s := range it.Statuses {
			out = append(out, ticketmap.WorkflowStatus{ID: s.ID, Name: s.Name, Category: s.StatusCategory.Key})
		}
	}
	return out, nil
}

// ListResolutions lists the site's resolutions.
func (c *Client) ListResolutions(ctx context.Context) ([]ticketmap.AllowedValue, error) {
	var resp []rawAllowed
	if err := c.doJSON(ctx, http.MethodGet, "/rest/api/2/resolution", nil, &resp); err != nil {
		return nil, err
	}
	out := make([]ticketmap.AllowedValue, 0, len(resp))
	for _, r := range resp {
		out = append(out, ticketmap.AllowedValue{ID: r.ID, Name: r.Name})
	}
	return out, nil
}

// ListWorkflowTransitions reads the transitions of the workflow of a project
// and issue type through the workflow read API (cloud sites). Data Center
// and sites without the API return (nil, nil): the editor then checks paths
// at run time, issue by issue, and says so.
func (c *Client) ListWorkflowTransitions(ctx context.Context, projectID, issueTypeID string) ([]ticketmap.WorkflowTransition, error) {
	if projectID == "" {
		return nil, nil
	}
	var resp struct {
		Workflows []struct {
			Statuses []struct {
				StatusReference string `json:"statusReference"`
			} `json:"statuses"`
			Transitions []struct {
				ID                string `json:"id"`
				Name              string `json:"name"`
				Type              string `json:"type"`
				ToStatusReference string `json:"toStatusReference"`
				Links             []struct {
					FromStatusReference string `json:"fromStatusReference"`
				} `json:"links"`
			} `json:"transitions"`
		} `json:"workflows"`
		Statuses []struct {
			ID              string `json:"id"`
			StatusReference string `json:"statusReference"`
		} `json:"statuses"`
	}
	body := map[string]any{"projectAndIssueTypes": []map[string]string{{"projectId": projectID, "issueTypeId": issueTypeID}}}
	if err := c.doJSON(ctx, http.MethodPost, "/rest/api/3/workflows", body, &resp); err != nil {
		var ue *httpsec.UpstreamStatusError
		if asUpstream(err, &ue) && (ue.Status == http.StatusNotFound || ue.Status == http.StatusMethodNotAllowed || ue.Status == http.StatusForbidden) {
			return nil, nil
		}
		return nil, err
	}
	ref := map[string]string{}
	for _, s := range resp.Statuses {
		ref[s.StatusReference] = s.ID
	}
	var out []ticketmap.WorkflowTransition
	for _, wf := range resp.Workflows {
		for _, t := range wf.Transitions {
			to := ref[t.ToStatusReference]
			if to == "" {
				continue
			}
			tr := ticketmap.WorkflowTransition{ID: t.ID, Name: t.Name, To: to}
			if t.Type != "GLOBAL" {
				for _, l := range t.Links {
					if f := ref[l.FromStatusReference]; f != "" {
						tr.From = append(tr.From, f)
					}
				}
				if len(tr.From) == 0 {
					continue // initial transition (create): not usable on an issue
				}
			}
			out = append(out, tr)
		}
	}
	return out, nil
}

// IssueTransition is a transition available on one issue now, with its
// screen fields.
type IssueTransition struct {
	ID     string
	Name   string
	To     ticketmap.WorkflowStatus
	Fields []ticketmap.TransitionField
}

// GetIssueTransitions lists the transitions available on an issue, with
// their screen fields (required flag and allowed values).
func (c *Client) GetIssueTransitions(ctx context.Context, issueKey string) ([]IssueTransition, error) {
	var resp struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			To   struct {
				ID             string `json:"id"`
				Name           string `json:"name"`
				StatusCategory struct {
					Key string `json:"key"`
				} `json:"statusCategory"`
			} `json:"to"`
			Fields map[string]rawField `json:"fields"`
		} `json:"transitions"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/rest/api/2/issue/"+url.PathEscape(issueKey)+"/transitions?expand=transitions.fields", nil, &resp); err != nil {
		return nil, err
	}
	out := make([]IssueTransition, 0, len(resp.Transitions))
	for _, t := range resp.Transitions {
		it := IssueTransition{ID: t.ID, Name: t.Name, To: ticketmap.WorkflowStatus{ID: t.To.ID, Name: t.To.Name, Category: t.To.StatusCategory.Key}}
		for id, f := range t.Fields {
			m := f.meta()
			it.Fields = append(it.Fields, ticketmap.TransitionField{ID: id, Name: m.Name, Required: m.Required, AllowedValues: m.AllowedValues})
		}
		out = append(out, it)
	}
	return out, nil
}

// GetIssueFields reads selected fields of an issue (inbound preview).
func (c *Client) GetIssueFields(ctx context.Context, issueKey string, fieldIDs []string) (map[string]json.RawMessage, error) {
	q := url.Values{}
	if len(fieldIDs) > 0 {
		q.Set("fields", strings.Join(fieldIDs, ","))
	}
	var resp struct {
		ID     string                     `json:"id"`
		Key    string                     `json:"key"`
		Fields map[string]json.RawMessage `json:"fields"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/rest/api/2/issue/"+url.PathEscape(issueKey)+"?"+q.Encode(), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Fields, nil
}

// CreateIssueFields creates an issue from a rendered field payload (project
// and issue type are set here, by id).
func (c *Client) CreateIssueFields(ctx context.Context, projectKey, issueTypeID string, fields map[string]any) (*CreateIssueResult, error) {
	f := make(map[string]any, len(fields)+2)
	for k, v := range fields {
		f[k] = v
	}
	f["project"] = map[string]string{"key": projectKey}
	f["issuetype"] = map[string]string{"id": issueTypeID}
	var out CreateIssueResult
	if err := c.doJSON(ctx, http.MethodPost, "/rest/api/2/issue", map[string]any{"fields": f}, &out); err != nil {
		return nil, err
	}
	out.BrowseURL = c.baseURL + "/browse/" + out.Key
	return &out, nil
}

func asUpstream(err error, target **httpsec.UpstreamStatusError) bool {
	return errors.As(err, target)
}

// IssueStatus is an issue's current workflow status.
type IssueStatus struct {
	ID       string
	Name     string
	Category string
}

// GetIssueStatusRef reads an issue's current status with its id and category.
func (c *Client) GetIssueStatusRef(ctx context.Context, issueKey string) (IssueStatus, error) {
	var resp struct {
		Fields struct {
			Status struct {
				ID             string `json:"id"`
				Name           string `json:"name"`
				StatusCategory struct {
					Key string `json:"key"`
				} `json:"statusCategory"`
			} `json:"status"`
		} `json:"fields"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/rest/api/2/issue/"+url.PathEscape(issueKey)+"?fields=status", nil, &resp); err != nil {
		return IssueStatus{}, err
	}
	s := resp.Fields.Status
	return IssueStatus{ID: s.ID, Name: s.Name, Category: s.StatusCategory.Key}, nil
}

// DoTransitionWithFields moves an issue through a transition, setting screen
// fields (the resolution by name, other fields as given) and an optional
// comment in the same call.
func (c *Client) DoTransitionWithFields(ctx context.Context, issueKey, transitionID string, fields map[string]string, comment string) error {
	body := map[string]any{"transition": map[string]string{"id": transitionID}}
	if len(fields) > 0 {
		f := make(map[string]any, len(fields))
		for id, v := range fields {
			if id == "resolution" {
				f[id] = map[string]string{"name": v}
				continue
			}
			f[id] = v
		}
		body["fields"] = f
	}
	if comment != "" {
		body["update"] = map[string]any{"comment": []map[string]any{{"add": map[string]string{"body": comment}}}}
	}
	return c.doJSON(ctx, http.MethodPost, "/rest/api/2/issue/"+url.PathEscape(issueKey)+"/transitions", body, nil)
}

// GetIssueIdentity reads an issue's id and current key (a moved issue answers
// with its new key). An issue the credentials cannot see is ErrIssueNotVisible.
func (c *Client) GetIssueIdentity(ctx context.Context, issueKey string) (id, key string, err error) {
	var resp struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/rest/api/2/issue/"+url.PathEscape(issueKey)+"?fields=project", nil, &resp); err != nil {
		var ue *httpsec.UpstreamStatusError
		if errors.As(err, &ue) && (ue.Status == http.StatusNotFound || ue.Status == http.StatusForbidden) {
			return "", "", ErrIssueNotVisible
		}
		return "", "", err
	}
	return resp.ID, resp.Key, nil
}

// ErrIssueNotVisible: the issue does not exist or the credentials cannot see it.
var ErrIssueNotVisible = errors.New("jira issue not found or not visible")
