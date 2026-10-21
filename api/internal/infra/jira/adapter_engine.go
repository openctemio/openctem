package jira

import (
	"context"
	"errors"
	"net/http"

	appjira "github.com/openctemio/openctem/api/internal/app/jira"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// The capabilities the mapping-profile engine needs, on the same adapter.

var (
	_ appjira.ProfileClient = clientAdapter{}
)

// IntegrationID is the integration the client was built from.
func (a clientAdapter) IntegrationID() shared.ID { return a.integrationID }

// CreateIssueFields creates an issue from a rendered field payload.
func (a clientAdapter) CreateIssueFields(ctx context.Context, projectKey, issueTypeID string, fields map[string]any, marker *appjira.IssueMarker) (*appjira.CreateIssueResult, error) {
	res, err := a.c.CreateIssueFields(ctx, projectKey, issueTypeID, fields, infraMarker(marker))
	if err != nil {
		return nil, mapUpstream(err)
	}
	return &appjira.CreateIssueResult{ID: res.ID, Key: res.Key, BrowseURL: res.BrowseURL}, nil
}

// infraMarker converts the app-layer marker.
func infraMarker(m *appjira.IssueMarker) *IssueMarker {
	if m == nil {
		return nil
	}
	return &IssueMarker{Object: m.Object, Kind: m.Kind, Integration: m.Integration}
}

// FindIssuesByMarker lists the issues labeled for the marker's object with
// the marker each one carries.
func (a clientAdapter) FindIssuesByMarker(ctx context.Context, m appjira.IssueMarker) ([]appjira.MarkedIssue, error) {
	issues, err := a.c.FindIssuesByMarker(ctx, m.Object)
	if err != nil {
		return nil, mapUpstream(err)
	}
	out := make([]appjira.MarkedIssue, 0, len(issues))
	for _, i := range issues {
		out = append(out, appjira.MarkedIssue{ID: i.ID, Key: i.Key, BrowseURL: i.BrowseURL,
			Marker: appjira.IssueMarker{Object: i.Marker.Object, Kind: i.Marker.Kind, Integration: i.Marker.Integration}})
	}
	return out, nil
}

// CurrentStatus reads the issue's status with id and category.
func (a clientAdapter) CurrentStatus(ctx context.Context, issueKey string) (ticketmap.WorkflowStatus, error) {
	s, err := a.c.GetIssueStatusRef(ctx, issueKey)
	if err != nil {
		return ticketmap.WorkflowStatus{}, mapUpstream(err)
	}
	return ticketmap.WorkflowStatus{ID: s.ID, Name: s.Name, Category: s.Category}, nil
}

// AvailableTransitions lists the transitions available on the issue now.
func (a clientAdapter) AvailableTransitions(ctx context.Context, issueKey string) ([]ticketmap.WorkflowTransition, error) {
	ts, err := a.c.GetIssueTransitions(ctx, issueKey)
	if err != nil {
		return nil, mapUpstream(err)
	}
	out := make([]ticketmap.WorkflowTransition, 0, len(ts))
	for _, t := range ts {
		out = append(out, ticketmap.WorkflowTransition{ID: t.ID, Name: t.Name, To: t.To.ID, Fields: t.Fields})
	}
	return out, nil
}

// Transition runs one transition with screen fields and a comment.
func (a clientAdapter) Transition(ctx context.Context, issueKey, transitionID string, fields map[string]string, comment string) error {
	return mapUpstream(a.c.DoTransitionWithFields(ctx, issueKey, transitionID, fields, comment))
}

// mapUpstream turns a rate limit into the app-layer sentinel and a 4xx into a
// permanent error, so the job does not retry what cannot succeed.
func mapUpstream(err error) error {
	if err == nil {
		return nil
	}
	var fr *FieldRejectedError
	if errors.As(err, &fr) {
		if out := appjira.NewFieldRejectedError(fr.Fields); out != nil {
			return out
		}
	}
	var rl *RateLimitedError
	if errors.As(err, &rl) {
		return &appjira.RetryAfterError{After: rl.RetryAfter}
	}
	var ue *httpsec.UpstreamStatusError
	if errors.As(err, &ue) && ue.Status >= 400 && ue.Status < 500 && ue.Status != http.StatusTooManyRequests && ue.Status != http.StatusConflict {
		return &appjira.PermanentError{Status: ue.Status, Err: err}
	}
	return err
}

// IssueIdentity reads an issue's id and current key.
func (a clientAdapter) IssueIdentity(ctx context.Context, issueKey string) (string, string, error) {
	id, key, err := a.c.GetIssueIdentity(ctx, issueKey)
	if errors.Is(err, ErrIssueNotVisible) {
		return "", "", appjira.ErrIssueNotVisible
	}
	return id, key, mapUpstream(err)
}

// IssueTypeOf reads the issue's current issue type id.
func (a clientAdapter) IssueTypeOf(ctx context.Context, issueKey string) (string, error) {
	id, err := a.c.GetIssueTypeID(ctx, issueKey)
	return id, mapUpstream(err)
}
