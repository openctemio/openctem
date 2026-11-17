package remediation

// Who may read the text of a task's query (docs/rfcs/RFC-098-remediation-tasks.md,
// "Tasks from a query"). The stored text is what its author typed: it can name
// assets, addresses or people outside the data scope of someone who sees the
// task through one in-scope finding. The full text goes to the query's owner,
// administrators and full-data roles; any other reader gets it with its
// literals masked (querylang.Redact), so the fields and operators still say
// what the task selects.

import (
	"context"

	remediationdom "github.com/openctemio/openctem/server/pkg/domain/remediation"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/pagination"
	"github.com/openctemio/openctem/server/pkg/querylang"
)

// Timeline data keys of a task created from a query.
const (
	timelineQueryKey         = "query"
	timelineQueryRedactedKey = "query_redacted"
)

// mayReadQueryText reports whether the request's caller may read the full
// text of a query owned by owner: its owner, an administrator or a
// full-data role, or internal work that is not on behalf of a person.
func (s *TaskService) mayReadQueryText(ctx context.Context, tenantID shared.ID, owner *shared.ID) (bool, error) {
	if s.dataScope == nil {
		return true, nil
	}
	c := s.dataScope.CallerOf(ctx)
	if c.UserID == "" && !c.APIKey {
		return true, nil
	}
	if owner != nil && c.UserID != "" && c.UserID == owner.String() {
		return true, nil
	}
	scope, err := s.resolveScope(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return !scope.Restricted(), nil
}

// redactedQueryText is text with its literals masked; "" when it does not
// parse (nothing is shown rather than the raw text).
func redactedQueryText(text string) string {
	out, ok := querylang.Redact(text)
	if !ok {
		return ""
	}
	return out
}

// queryTextFor returns text as the caller may read it, and whether it was
// masked.
func (s *TaskService) queryTextFor(ctx context.Context, tenantID shared.ID, owner *shared.ID, text string) (string, bool, error) {
	full, err := s.mayReadQueryText(ctx, tenantID, owner)
	if err != nil {
		return "", true, err
	}
	if full {
		return text, false, nil
	}
	return redactedQueryText(text), true, nil
}

// readableQuery is a copy of q whose text the caller may read.
func (s *TaskService) readableQuery(ctx context.Context, tenantID shared.ID, q *remediationdom.TaskQuery) (*remediationdom.TaskQuery, error) {
	if q == nil {
		return nil, nil
	}
	text, redacted, err := s.queryTextFor(ctx, tenantID, q.OwnerUserID, q.Text)
	if err != nil {
		return nil, err
	}
	out := *q
	out.Text, out.TextRedacted = text, redacted
	return &out, nil
}

// redactTimelineQueries masks, in place, the query text the timeline entries
// carry when the caller may not read it in full.
func (s *TaskService) redactTimelineQueries(ctx context.Context, tenantID, taskID shared.ID, res pagination.Result[remediationdom.TaskEvent]) error {
	has := false
	for _, e := range res.Data {
		if _, ok := e.Data[timelineQueryKey]; ok {
			has = true
			break
		}
	}
	if !has {
		return nil
	}
	var owner *shared.ID
	if s.queries != nil {
		q, err := s.queries.GetTaskQuery(ctx, tenantID, taskID)
		if err == nil {
			owner = q.OwnerUserID
		}
	}
	full, err := s.mayReadQueryText(ctx, tenantID, owner)
	if err != nil || full {
		return err
	}
	for _, e := range res.Data {
		v, ok := e.Data[timelineQueryKey]
		if !ok {
			continue
		}
		text, _ := v.(string)
		e.Data[timelineQueryKey] = redactedQueryText(text)
		e.Data[timelineQueryRedactedKey] = true
	}
	return nil
}
