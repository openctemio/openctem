package scanrun

// Paging through a run's tasks with a keyset cursor (RFC-046 §4.1, RFC-048
// §3.5 cursor). See docs/rfcs/RFC-046-scans-redesign.md.

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TaskCursor is the position after the last task of a page, in dispatch order
// (created_at, id).
type TaskCursor struct {
	CreatedAt time.Time
	ID        shared.ID
}

// MaxTaskCursorLen bounds an encoded cursor before it is decoded.
const MaxTaskCursorLen = 128

// Encode returns the opaque cursor string (base64url, no padding).
func (c TaskCursor) Encode() string {
	raw := c.CreatedAt.UTC().Format(time.RFC3339Nano) + "|" + c.ID.String()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// TaskCursorAfter is the cursor that continues after task t.
func TaskCursorAfter(t Task) TaskCursor {
	return TaskCursor{CreatedAt: t.CreatedAt, ID: t.ID}
}

// DecodeTaskCursor parses an opaque cursor. Anything that is not exactly a
// cursor this package encoded is a validation error; a forged but well-formed
// cursor can only reposition a read inside the caller's own run.
func DecodeTaskCursor(s string) (TaskCursor, error) {
	invalid := fmt.Errorf("%w: invalid cursor", shared.ErrValidation)
	if s == "" || len(s) > MaxTaskCursorLen {
		return TaskCursor{}, invalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return TaskCursor{}, invalid
	}
	ts, id, ok := strings.Cut(string(raw), "|")
	if !ok {
		return TaskCursor{}, invalid
	}
	at, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return TaskCursor{}, invalid
	}
	sid, err := shared.IDFromString(id)
	if err != nil {
		return TaskCursor{}, invalid
	}
	return TaskCursor{CreatedAt: at, ID: sid}, nil
}

// TaskPager pages through the tasks of a run in dispatch order. Every read is
// scoped to tenantID: a run of another tenant has no tasks.
type TaskPager interface {
	// ListRunTasksAfter returns up to limit tasks of runID that come after
	// the cursor (from the first task when after is nil).
	ListRunTasksAfter(ctx context.Context, tenantID, runID shared.ID, after *TaskCursor, limit int) ([]Task, error)
}
