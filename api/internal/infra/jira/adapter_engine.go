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
func (a clientAdapter) CreateIssueFields(ctx context.Context, projectKey, issueTypeID string, fields map[string]any) (*appjira.CreateIssueResult, error) {
	res, err := a.c.CreateIssueFields(ctx, projectKey, issueTypeID, fields)
	if err != nil {
		return nil, mapUpstream(err)
	}
	return &appjira.CreateIssueResult{ID: res.ID, Key: res.Key, BrowseURL: res.BrowseURL}, nil
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
