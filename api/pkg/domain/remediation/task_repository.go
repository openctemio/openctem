package remediation

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// NewTaskRecord is what CreateTask stores in one transaction.
type NewTaskRecord struct {
	// Action: an existing action (ID set) or a new one to create (ID zero;
	// an action with the same key is reused).
	Action  Action
	Task    Task
	Members []shared.ID // primary members
	Related []shared.ID
	Source  JoinSource
	ActorID *shared.ID
	// OneActive makes the create fail with ErrActiveTaskExists when the action
	// already has an open or in-progress task (concurrent creators of the same
	// action are serialized on the action row). Other creators, such as a split
	// or a route accept, may open several tasks on one action and leave it false.
	OneActive bool
	// EventData is stored on the "created" timeline entry.
	EventData map[string]any
	// Conflicts resolves members that belong to another active task (zero
	// value: refuse them with a *FindingsInOtherTaskError).
	Conflicts ConflictResolution
	// Claimed is set by CreateTask: the members skipped or moved.
	Claimed ClaimReport
	// Query is the custom query the task was created from, stored in the
	// same transaction (nil for every other task).
	Query *TaskQuery
}

// AddMembersRequest adds findings to a task at the caller's version.
type AddMembersRequest struct {
	TenantID        shared.ID
	TaskID          shared.ID
	ExpectedVersion int
	FindingIDs      []shared.ID
	Role            MemberRole
	Source          JoinSource
	ActorID         *shared.ID
	// Conflicts resolves primary findings of another active task.
	Conflicts ConflictResolution
}

// TaskChanges are the editable fields of a task; nil leaves a field as is.
type TaskChanges struct {
	Title           *string
	Description     *string
	AssigneeUserID  **shared.ID
	AssigneeGroupID **shared.ID
	ManualDeadline  **time.Time
	CampaignID      **shared.ID
	// ManualState: set to a pointer to nil to resume a held task.
	ManualState     **ManualState
	ManualStateNote *string
}

// StaleTaskRef names a task whose members changed since it was last
// recomputed.
type StaleTaskRef struct {
	TenantID shared.ID
	TaskID   shared.ID
}

// MemberFilter narrows a member list.
type MemberFilter struct {
	Role   MemberRole // "" = both
	Status string     // "open" | "closed" | a finding status | ""
	Scope  *shared.DataScope
}

// TaskRepository stores remediation actions and tasks. Every method is
// scoped to one tenant except the ones named ForPlatform.
type TaskRepository interface {
	GetTask(ctx context.Context, tenantID, taskID shared.ID) (*Task, error)
	GetAction(ctx context.Context, tenantID, actionID shared.ID) (*Action, error)
	ListTasks(ctx context.Context, tenantID shared.ID, f TaskFilter, page pagination.Pagination) (pagination.Result[*Task], error)
	CreateTask(ctx context.Context, rec *NewTaskRecord) error
	AddMembers(ctx context.Context, req AddMembersRequest) (*Task, *ClaimReport, error)
	// ActivePrimaryTasks maps each finding that is the primary member of an
	// active task to that task.
	ActivePrimaryTasks(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) (map[shared.ID]shared.ID, error)
	UpdateTask(ctx context.Context, tenantID, taskID shared.ID, expectedVersion int, ch TaskChanges, actor *shared.ID, eventKind string, eventData map[string]any) (*Task, error)
	Recompute(ctx context.Context, tenantID shared.ID, taskIDs []shared.ID, actor *shared.ID) error
	ScopedCounts(ctx context.Context, tenantID shared.ID, taskIDs []shared.ID, scope *shared.DataScope) (map[shared.ID]TaskCounts, error)
	ListMembers(ctx context.Context, tenantID, taskID shared.ID, f MemberFilter, page pagination.Pagination) (pagination.Result[TaskMember], error)
	ListEvents(ctx context.Context, tenantID, taskID shared.ID, page pagination.Pagination) (pagination.Result[TaskEvent], error)
	FindingStatuses(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]string, error)
	CampaignInTenant(ctx context.Context, tenantID, campaignID shared.ID) (bool, error)
	// LiveTaskIDsByCampaign lists the campaign's tasks that still take work.
	LiveTaskIDsByCampaign(ctx context.Context, tenantID, campaignID shared.ID) ([]shared.ID, error)
	StaleTasksForPlatform(ctx context.Context, limit int) ([]StaleTaskRef, error)
	MoveMembers(ctx context.Context, m MoveRequest) (*MoveResult, error)
	SplitTask(ctx context.Context, sp SplitRequest) (shared.ID, *MoveResult, error)
	MergeTasks(ctx context.Context, mg MergeRequest) (map[shared.ID]int, error)
	CountActivePrimary(ctx context.Context, tenantID, taskID shared.ID, ids []shared.ID) (int, error)
	OpenPrimaryIDs(ctx context.Context, tenantID, taskID shared.ID) ([]shared.ID, error)
	RecordFixClaim(ctx context.Context, tenantID, taskID shared.ID, actor *shared.ID, data map[string]any) error
}
