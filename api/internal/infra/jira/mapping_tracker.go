package jira

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	appticketmap "github.com/openctemio/openctem/api/internal/app/ticketmap"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// MappingTrackerResolver opens the Jira site of one integration for the
// mapping editor. The integration is loaded tenant-scoped, so another
// tenant's integration id is "not found".
type MappingTrackerResolver struct {
	resolver *IntegrationClientResolver
}

// NewMappingTrackerResolver builds the resolver on the credential resolver.
func NewMappingTrackerResolver(r *IntegrationClientResolver) *MappingTrackerResolver {
	return &MappingTrackerResolver{resolver: r}
}

var _ appticketmap.TrackerResolver = (*MappingTrackerResolver)(nil)

// ErrNotATracker: the integration is not a connected Jira site.
var ErrNotATracker = fmt.Errorf("%w: the integration is not a connected Jira site", shared.ErrValidation)

// ForIntegration returns the tracker of a connected Jira integration of the
// tenant.
func (m *MappingTrackerResolver) ForIntegration(ctx context.Context, tenantID, integrationID shared.ID) (appticketmap.Tracker, error) {
	intg, err := m.resolver.integrationRepo.GetByTenantAndID(ctx, tenantID, integrationID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, fmt.Errorf("%w: integration not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("load integration: %w", err)
	}
	if intg.TenantID() != tenantID {
		return nil, fmt.Errorf("%w: integration not found", shared.ErrNotFound)
	}
	if intg.Provider() != integration.ProviderJira || intg.Status() != integration.StatusConnected {
		return nil, ErrNotATracker
	}
	baseURL := intg.BaseURL()
	if baseURL == "" {
		baseURL = stringFromMap(intg.Config(), "base_url")
	}
	email, token, err := m.resolver.resolveCredentials(intg)
	if err != nil {
		return nil, ErrNotATracker
	}
	c, err := NewClient(baseURL, email, token)
	if err != nil {
		return nil, ErrNotATracker
	}
	return &trackerAdapter{c: c}, nil
}

// trackerAdapter adapts the Jira client to the mapping service's Tracker.
type trackerAdapter struct{ c *Client }

func (t *trackerAdapter) IssueTypes(ctx context.Context, projectKey string) ([]appticketmap.IssueTypeRef, error) {
	types, err := t.c.ListIssueTypes(ctx, projectKey)
	if err != nil {
		return nil, err
	}
	out := make([]appticketmap.IssueTypeRef, 0, len(types))
	for _, it := range types {
		out = append(out, appticketmap.IssueTypeRef{ID: it.ID, Name: it.Name, Subtask: it.Subtask})
	}
	return out, nil
}

func (t *trackerAdapter) ProjectMeta(ctx context.Context, projectKey, projectID, issueTypeID string) (*ticketmap.ProjectMeta, error) {
	fields, err := t.c.ListCreateFields(ctx, projectKey, issueTypeID)
	if err != nil {
		return nil, err
	}
	meta := &ticketmap.ProjectMeta{ProjectKey: projectKey, ProjectID: projectID, IssueTypeID: issueTypeID, Fields: fields}
	if meta.ProjectID == "" {
		var p struct {
			ID string `json:"id"`
		}
		if err := t.c.doJSON(ctx, http.MethodGet, "/rest/api/2/project/"+url.PathEscape(projectKey), nil, &p); err == nil {
			meta.ProjectID = p.ID
		}
	}
	if types, err := t.c.ListIssueTypes(ctx, projectKey); err == nil {
		for _, it := range types {
			if it.ID == issueTypeID {
				meta.IssueType = it.Name
			}
		}
	}
	// The workflow is best-effort: a site without the endpoints still gets
	// field checks, and validation says what it could not check.
	if st, err := t.c.ListProjectStatuses(ctx, projectKey, issueTypeID); err == nil {
		meta.Workflow.Statuses = st
	}
	if res, err := t.c.ListResolutions(ctx); err == nil {
		meta.Workflow.Resolutions = res
	}
	if tr, err := t.c.ListWorkflowTransitions(ctx, meta.ProjectID, issueTypeID); err == nil {
		meta.Workflow.Transitions = keepKnown(tr, meta.Workflow.Statuses)
	}
	return meta, nil
}

// keepKnown drops transitions to or from statuses the project does not use.
func keepKnown(tr []ticketmap.WorkflowTransition, statuses []ticketmap.WorkflowStatus) []ticketmap.WorkflowTransition {
	known := map[string]bool{}
	for _, s := range statuses {
		known[s.ID] = true
	}
	out := make([]ticketmap.WorkflowTransition, 0, len(tr))
	for _, t := range tr {
		if !known[t.To] {
			continue
		}
		from := t.From[:0:0]
		for _, f := range t.From {
			if known[f] {
				from = append(from, f)
			}
		}
		if len(t.From) > 0 && len(from) == 0 {
			continue
		}
		t.From = from
		out = append(out, t)
	}
	return out
}

func (t *trackerAdapter) Issue(ctx context.Context, issueKey string, fieldIDs []string) (*appticketmap.IssueSnapshot, error) {
	ids := append([]string{"status", "resolution"}, fieldIDs...)
	raw, err := t.c.GetIssueFields(ctx, issueKey, ids)
	if err != nil {
		var ue *httpsec.UpstreamStatusError
		if errors.As(err, &ue) && ue.Status == http.StatusNotFound {
			return nil, fmt.Errorf("%w: issue not found", shared.ErrNotFound)
		}
		return nil, err
	}
	snap := &appticketmap.IssueSnapshot{Key: issueKey, Fields: map[string]string{}}
	var status struct {
		ID             string `json:"id"`
		Name           string `json:"name"`
		StatusCategory struct {
			Key string `json:"key"`
		} `json:"statusCategory"`
	}
	if b, ok := raw["status"]; ok {
		_ = json.Unmarshal(b, &status)
	}
	snap.StatusID, snap.StatusName, snap.Category = status.ID, status.Name, status.StatusCategory.Key
	var res struct {
		Name string `json:"name"`
	}
	if b, ok := raw["resolution"]; ok {
		_ = json.Unmarshal(b, &res)
	}
	snap.Resolution = res.Name
	for _, id := range fieldIDs {
		if b, ok := raw[id]; ok {
			snap.Fields[id] = displayValue(b)
		}
	}
	return snap, nil
}

// displayValue reduces a field's JSON to the string an inbound mapping uses:
// an account id for users, the name or value of an option, a plain string.
func displayValue(b json.RawMessage) string {
	var s string
	if json.Unmarshal(b, &s) == nil {
		return s
	}
	var obj map[string]any
	if json.Unmarshal(b, &obj) == nil {
		for _, k := range []string{"accountId", "name", "value", "key"} {
			if v, ok := obj[k].(string); ok && v != "" {
				return v
			}
		}
	}
	var n float64
	if json.Unmarshal(b, &n) == nil {
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", n), "0"), ".")
	}
	return ""
}
