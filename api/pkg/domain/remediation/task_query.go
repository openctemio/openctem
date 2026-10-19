package remediation

// Tasks created from a custom query: docs/rfcs/RFC-098-remediation-tasks.md,
// "Tasks from a query".
//
// The query is stored with the task. In snapshot mode the task holds the
// matches at creation; a re-run shows new matches and adds them only on the
// person's confirmation. In auto mode a worker adds new matches that no
// other active task holds, up to the task's cap, always as the query's
// owner with that person's current access, and suspends itself when the
// owner leaves or loses access.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// QueryMode is how a query task's membership follows its query.
type QueryMode string

const (
	// QueryModeSnapshot: the matches at creation; new matches join only on
	// confirmation.
	QueryModeSnapshot QueryMode = "snapshot"
	// QueryModeAuto: new matches join automatically.
	QueryModeAuto QueryMode = "auto"
)

// IsValid reports whether m is a known mode.
func (m QueryMode) IsValid() bool { return m == QueryModeSnapshot || m == QueryModeAuto }

// AutoState is the state of auto mode.
type AutoState string

const (
	AutoStateActive AutoState = "active"
	// AutoStatePaused: a person paused it; resuming is one click.
	AutoStatePaused AutoState = "paused"
	// AutoStateSuspended: the platform stopped it (AutoReason says why).
	AutoStateSuspended AutoState = "suspended"
)

// AutoReason is why auto mode was suspended.
type AutoReason string

const (
	// AutoReasonOwnerRemoved: the query's owner left the organization or
	// the account was deleted.
	AutoReasonOwnerRemoved AutoReason = "owner_removed"
	// AutoReasonOwnerLostAccess: the owner no longer holds the permissions
	// a run needs (findings read and remediation write).
	AutoReasonOwnerLostAccess AutoReason = "owner_lost_access"
	// AutoReasonTaskClosed: the task is closed, canceled or archived.
	AutoReasonTaskClosed AutoReason = "task_closed"
	// AutoReasonQueryInvalid: the stored query no longer compiles (a field
	// was removed, or the owner may no longer use one of its fields).
	AutoReasonQueryInvalid AutoReason = "query_invalid"
)

// Limits.
const (
	// MaxFindingsPerQueryTask caps a task created from a query; a larger
	// result is narrowed or split into several tasks under a campaign.
	MaxFindingsPerQueryTask = 1000
	// MaxTaskQueryText bounds the stored query text.
	MaxTaskQueryText = 4096
	// QueryPreviewSample is the number of sample rows a preview returns.
	QueryPreviewSample = 20
)

// TaskQuery is the query a task was created from.
type TaskQuery struct {
	TaskID         shared.ID
	TenantID       shared.ID
	Text           string
	Version        int
	Mode           QueryMode
	AutoState      *AutoState
	AutoReason     *AutoReason
	Cap            int
	OwnerUserID    *shared.ID
	LastRunAt      *time.Time
	LastAddedCount int
	TotalAdded     int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// NormalizeTaskQueryText trims a query and checks its length.
func NormalizeTaskQueryText(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("%w: query is required", shared.ErrValidation)
	}
	if len(s) > MaxTaskQueryText {
		return "", fmt.Errorf("%w: the query is longer than %d characters", shared.ErrValidation, MaxTaskQueryText)
	}
	return s, nil
}

// NormalizeQueryCap returns the cap to store: MaxFindingsPerQueryTask when
// unset, refused above it.
func NormalizeQueryCap(c int) (int, error) {
	switch {
	case c == 0:
		return MaxFindingsPerQueryTask, nil
	case c < 1 || c > MaxFindingsPerQueryTask:
		return 0, fmt.Errorf("%w: the cap must be between 1 and %d", shared.ErrValidation, MaxFindingsPerQueryTask)
	}
	return c, nil
}

// ErrTooManyMatches: the query selects more findings than one task holds.
var ErrTooManyMatches = shared.NewDomainError("QUERY_TOO_MANY_MATCHES",
	fmt.Sprintf("The query selects more than %d findings, the most one task holds. Narrow it, or split the work into several tasks under a campaign.", MaxFindingsPerQueryTask),
	shared.ErrValidation)

// ErrTaskNotFromQuery: the task was not created from a query.
var ErrTaskNotFromQuery = fmt.Errorf("%w: the task was not created from a query", shared.ErrNotFound)

// ErrNotAutoMode: pause and resume apply to auto mode only.
var ErrNotAutoMode = fmt.Errorf("%w: the task does not add new matches automatically", shared.ErrValidation)

// ErrAutoSuspended: a suspended task resumes only once its cause is gone
// (a new owner takes it over, or access is restored).
var ErrAutoSuspended = fmt.Errorf("%w: auto mode was suspended; it resumes after its cause is resolved", shared.ErrConflict)

// QueryClaim adds findings found by a task's query: only findings that no
// active task holds, up to the task's cap. Findings another active task
// holds are skipped (never taken), so the one-task rule holds.
type QueryClaim struct {
	TenantID shared.ID
	TaskID   shared.ID
	IDs      []shared.ID
	Cap      int
	ActorID  *shared.ID
	// Auto marks an automatic addition (timeline actor "system" on behalf
	// of the owner).
	Auto bool
}

// QueryClaimResult is what a query claim did.
type QueryClaimResult struct {
	Added   []shared.ID
	Skipped []shared.ID // held by another active task, or already members
	Capped  []shared.ID // left out by the cap
}

// DueQueryTask names an auto task due for a run.
type DueQueryTask struct {
	TenantID shared.ID
	TaskID   shared.ID
}

// PrimaryHolder is the active task a finding is the primary member of.
type PrimaryHolder struct {
	FindingID       shared.ID
	FindingTitle    string
	TaskID          shared.ID
	TaskTitle       string
	AssigneeUserID  *shared.ID
	AssigneeGroupID *shared.ID
}

// TaskQueryRepository stores task queries. Every method is scoped to one
// tenant except the one named ForPlatform.
type TaskQueryRepository interface {
	GetTaskQuery(ctx context.Context, tenantID, taskID shared.ID) (*TaskQuery, error)
	SetAutoState(ctx context.Context, tenantID, taskID shared.ID, state AutoState, reason *AutoReason) error
	RecordQueryRun(ctx context.Context, tenantID, taskID shared.ID, added int, at time.Time) error
	ClaimQueryFindings(ctx context.Context, c QueryClaim) (*QueryClaimResult, error)
	PrimaryHolders(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]PrimaryHolder, error)
	DueAutoQueryTasksForPlatform(ctx context.Context, olderThan time.Time, limit int) ([]DueQueryTask, error)
}

// QueryBreakdown is one row of a preview breakdown.
type QueryBreakdown struct {
	Key   string // a severity, an asset id or an owner key
	Name  string
	Count int
	// UserID or GroupID name an owner row.
	UserID  *shared.ID
	GroupID *shared.ID
}

// QuerySampleRow is one sample finding of a preview.
type QuerySampleRow struct {
	FindingID   shared.ID
	Title       string
	Severity    string
	Status      string
	AssetID     *shared.ID
	AssetName   string
	SLADeadline *time.Time
}

// QueryPreviewStats are the breakdowns of a set of findings a query
// matched (all in the caller's scope: the ids come from the caller's run).
type QueryPreviewStats struct {
	Severity         []QueryBreakdown
	Assets           []QueryBreakdown // top assets by count
	Owners           []QueryBreakdown // the assets' primary owners, top by count
	Sample           []QuerySampleRow
	EarliestDeadline *time.Time
}

// QueryPreviewReader reads preview breakdowns.
type QueryPreviewReader interface {
	QueryPreviewStats(ctx context.Context, tenantID shared.ID, ids []shared.ID, sample int) (*QueryPreviewStats, error)
}
