package sensor

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Timeline item sources.
const (
	ActivitySourceSensor = "sensor" // sensor_events, written by the server
	ActivitySourceAudit  = "audit"  // the audit log (administrator actions)
	ActivitySourceJob    = "job"    // the commands table
)

// Timeline item types that are not server-written events.
const (
	ActivityTypeAudit        = "audit"
	ActivityTypeJobClaimed   = "job_claimed"
	ActivityTypeJobCompleted = "job_completed"
	ActivityTypeJobFailed    = "job_failed"
	ActivityTypeJobCanceled  = "job_canceled"
	ActivityTypeJobExpired   = "job_expired"
)

// ActivityItem is one entry of a sensor's timeline.
type ActivityItem struct {
	// Key is unique and stable across reads ("e:<id>", "a:<id>",
	// "j:<id>:claim", "j:<id>:done"); with At it orders the timeline.
	Key         string
	At          time.Time
	Category    ActivityCategory
	Type        string
	Source      string
	Summary     string
	Details     map[string]any
	RepeatCount int
	LastAt      *time.Time
	// Action, Actor and Result are set on audit items only.
	Action string
	Actor  string
	Result string
}

// ActivityCursor is the position after the last item a page returned.
type ActivityCursor struct {
	At  time.Time
	Key string
}

// Encode returns the opaque cursor string.
func (c ActivityCursor) Encode() string {
	return base64.RawURLEncoding.EncodeToString([]byte(c.At.UTC().Format(time.RFC3339Nano) + "|" + c.Key))
}

// maxCursorLen bounds an incoming cursor.
const maxCursorLen = 256

// ParseActivityCursor decodes a cursor from Encode.
func ParseActivityCursor(s string) (*ActivityCursor, error) {
	if s == "" {
		return nil, nil
	}
	if len(s) > maxCursorLen {
		return nil, fmt.Errorf("%w: invalid cursor", shared.ErrValidation)
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid cursor", shared.ErrValidation)
	}
	at, key, ok := strings.Cut(string(raw), "|")
	if !ok || key == "" {
		return nil, fmt.Errorf("%w: invalid cursor", shared.ErrValidation)
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid cursor", shared.ErrValidation)
	}
	return &ActivityCursor{At: t, Key: key}, nil
}

// ActivityQuery selects one page of a sensor's timeline.
type ActivityQuery struct {
	TenantID   shared.ID
	SensorID   shared.ID
	Categories []ActivityCategory // non-empty
	// IncludeAudit admits audit-log items; false for callers without
	// audit:read.
	IncludeAudit bool
	After        *ActivityCursor
	// Limit is the page size; the reader returns up to Limit+1 items so the
	// caller can tell whether there is more.
	Limit int
}

// Has reports whether the query includes the category.
func (q ActivityQuery) Has(c ActivityCategory) bool {
	for _, x := range q.Categories {
		if x == c {
			return true
		}
	}
	return false
}

// ActivityReader reads a sensor's timeline: its events, its jobs and (when
// admitted) its audit rows, merged newest first.
type ActivityReader interface {
	ListActivity(ctx context.Context, q ActivityQuery) ([]ActivityItem, error)
}
