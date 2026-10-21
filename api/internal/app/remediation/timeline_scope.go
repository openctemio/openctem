package remediation

import (
	"context"

	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Timeline entries name the other task of a move, split or regression: its id
// and title, and a person's free-text reason for the move. A reader who cannot
// open that other task must not learn any of them, so the entry keeps only the
// counts and a marker.
var (
	// timelineTaskRefs maps the data key that holds another task's id to the
	// keys that describe that task.
	timelineTaskRefs = map[string][]string{
		"to_task_id":         {"to_task_title"},
		"from_task_id":       {"from_task_title"},
		"split_from":         {"split_from_title"},
		"regression_of":      {"regression_of_title"},
		"regression_task_id": nil,
		"new_task_id":        nil,
	}
	// timelineReasonKeys hold a person's text about a move between two tasks.
	timelineReasonKeys = []string{"move_reason"}
)

// TimelineHiddenKey marks an entry whose other task the reader cannot open.
const TimelineHiddenKey = "other_task_hidden"

// scopeEvents redacts, in place, what the events say about tasks the
// restricted reader cannot open (the same test as GetTask: at least one
// member in their scope). A reader without a data scope sees everything.
func (s *TaskService) scopeEvents(ctx context.Context, tenantID, taskID shared.ID, scope *shared.DataScope, events []remediationdom.TaskEvent) error {
	if scope == nil || len(events) == 0 {
		return nil
	}
	seen := map[shared.ID]bool{taskID: true}
	var ids []shared.ID
	for _, e := range events {
		for key := range timelineTaskRefs {
			id, ok := eventTaskRef(e.Data, key)
			if ok && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	visible := map[shared.ID]bool{taskID: true}
	if len(ids) > 0 {
		counts, err := s.repo.ScopedCounts(ctx, tenantID, ids, scope)
		if err != nil {
			return err
		}
		for _, id := range ids {
			c := counts[id]
			visible[id] = c.Total > 0 || c.Related > 0
		}
	}
	for _, e := range events {
		hidden := false
		for key, titles := range timelineTaskRefs {
			id, ok := eventTaskRef(e.Data, key)
			if !ok || visible[id] {
				continue
			}
			hidden = true
			delete(e.Data, key)
			for _, tk := range titles {
				delete(e.Data, tk)
			}
		}
		if hidden {
			for _, k := range timelineReasonKeys {
				delete(e.Data, k)
			}
			e.Data[TimelineHiddenKey] = true
		}
	}
	return nil
}

// eventTaskRef reads the task id stored under key. A value that is present
// but not a valid id counts as an unreadable task, so the caller redacts it.
func eventTaskRef(data map[string]any, key string) (shared.ID, bool) {
	v, ok := data[key]
	if !ok {
		return shared.ID{}, false
	}
	str, _ := v.(string)
	id, err := shared.IDFromString(str)
	if err != nil {
		return shared.ID{}, true
	}
	return id, true
}

// listEventsScoped is ListEvents after the caller was found able to open the
// task.
func (s *TaskService) listEventsScoped(ctx context.Context, tenantID, taskID shared.ID, page pagination.Pagination) (pagination.Result[remediationdom.TaskEvent], error) {
	scope, err := s.resolveScope(ctx, tenantID)
	if err != nil {
		return pagination.Result[remediationdom.TaskEvent]{}, err
	}
	res, err := s.repo.ListEvents(ctx, tenantID, taskID, page)
	if err != nil {
		return res, err
	}
	if err := s.scopeEvents(ctx, tenantID, taskID, scope, res.Data); err != nil {
		return pagination.Result[remediationdom.TaskEvent]{}, err
	}
	return res, nil
}
