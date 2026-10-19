// Package remediation provides domain models for remediation campaign management.
package remediation

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// CampaignStatus defines lifecycle states.
type CampaignStatus string

const (
	CampaignStatusDraft     CampaignStatus = "draft"
	CampaignStatusActive    CampaignStatus = "active"
	CampaignStatusCompleted CampaignStatus = "completed"
	CampaignStatusCanceled  CampaignStatus = "canceled"
)

// CampaignPriority defines urgency levels.
type CampaignPriority string

const (
	CampaignPriorityCritical CampaignPriority = "critical"
	CampaignPriorityHigh     CampaignPriority = "high"
	CampaignPriorityMedium   CampaignPriority = "medium"
	CampaignPriorityLow      CampaignPriority = "low"
)

// Campaign is a program of remediation tasks (remediation_tasks.campaign_id)
// with one owner and one due date. It holds tasks, never findings: what it
// covers and how far along it is are derived from its tasks (CampaignSummary).
type Campaign struct {
	id           shared.ID
	tenantID     shared.ID
	name         string
	description  string
	status       CampaignStatus
	priority     CampaignPriority
	assignedTo   *shared.ID
	assignedTeam *shared.ID
	startDate    *time.Time
	dueDate      *time.Time
	completedAt  *time.Time
	tags         []string
	createdBy    *shared.ID
	createdAt    time.Time
	updatedAt    time.Time
	// version is the optimistic-concurrency token: every full save checks it
	// and bumps it (CampaignRepository.Update).
	version int
}

// NewCampaign creates a new remediation campaign.
func NewCampaign(tenantID shared.ID, name string, priority CampaignPriority) (*Campaign, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	now := time.Now()
	return &Campaign{
		id:        shared.NewID(),
		tenantID:  tenantID,
		name:      name,
		status:    CampaignStatusDraft,
		priority:  priority,
		tags:      []string{},
		createdAt: now,
		updatedAt: now,
		version:   1,
	}, nil
}

// ReconstituteCampaign creates from persisted data.
func ReconstituteCampaign(
	id, tenantID shared.ID,
	name, description string,
	status CampaignStatus, priority CampaignPriority,
	assignedTo, assignedTeam *shared.ID,
	startDate, dueDate, completedAt *time.Time,
	tags []string, createdBy *shared.ID,
	createdAt, updatedAt time.Time,
	version int,
) *Campaign {
	return &Campaign{
		id: id, tenantID: tenantID,
		name: name, description: description,
		status: status, priority: priority,
		assignedTo: assignedTo, assignedTeam: assignedTeam,
		startDate: startDate, dueDate: dueDate, completedAt: completedAt,
		tags: tags, createdBy: createdBy,
		createdAt: createdAt, updatedAt: updatedAt,
		version: version,
	}
}

// Getters
func (c *Campaign) ID() shared.ID              { return c.id }
func (c *Campaign) TenantID() shared.ID        { return c.tenantID }
func (c *Campaign) Name() string               { return c.name }
func (c *Campaign) Description() string        { return c.description }
func (c *Campaign) Status() CampaignStatus     { return c.status }
func (c *Campaign) Priority() CampaignPriority { return c.priority }
func (c *Campaign) AssignedTo() *shared.ID     { return c.assignedTo }
func (c *Campaign) AssignedTeam() *shared.ID   { return c.assignedTeam }
func (c *Campaign) StartDate() *time.Time      { return c.startDate }
func (c *Campaign) DueDate() *time.Time        { return c.dueDate }
func (c *Campaign) CompletedAt() *time.Time    { return c.completedAt }
func (c *Campaign) Tags() []string             { return c.tags }
func (c *Campaign) CreatedBy() *shared.ID      { return c.createdBy }
func (c *Campaign) CreatedAt() time.Time       { return c.createdAt }
func (c *Campaign) UpdatedAt() time.Time       { return c.updatedAt }
func (c *Campaign) Version() int               { return c.version }

// SetVersion records the version the repository stored (after a save).
func (c *Campaign) SetVersion(v int) { c.version = v }

// ParseCampaignPriority accepts only the defined priorities.
func ParseCampaignPriority(s string) (CampaignPriority, error) {
	switch p := CampaignPriority(s); p {
	case CampaignPriorityCritical, CampaignPriorityHigh, CampaignPriorityMedium, CampaignPriorityLow:
		return p, nil
	}
	return "", fmt.Errorf("%w: priority must be one of critical, high, medium, low", shared.ErrValidation)
}

// Update sets mutable fields.
func (c *Campaign) Update(name, description string, priority CampaignPriority) {
	if name != "" {
		c.name = name
	}
	c.description = description
	c.priority = priority
	c.updatedAt = time.Now()
}

// SetAssignment sets who/what team is responsible.
func (c *Campaign) SetAssignment(assignedTo, assignedTeam *shared.ID) {
	c.assignedTo = assignedTo
	c.assignedTeam = assignedTeam
	c.updatedAt = time.Now()
}

// SetTimeline sets start and due dates.
func (c *Campaign) SetTimeline(startDate, dueDate *time.Time) {
	c.startDate = startDate
	c.dueDate = dueDate
	c.updatedAt = time.Now()
}

// SetName sets campaign name.
func (c *Campaign) SetName(name string) {
	c.name = name
	c.updatedAt = time.Now()
}

// SetDescription sets campaign description.
func (c *Campaign) SetDescription(desc string) {
	c.description = desc
	c.updatedAt = time.Now()
}

// SetPriority sets campaign priority.
func (c *Campaign) SetPriority(p CampaignPriority) {
	c.priority = p
	c.updatedAt = time.Now()
}

// SetStartDate sets campaign start date.
func (c *Campaign) SetStartDate(d *time.Time) {
	c.startDate = d
	c.updatedAt = time.Now()
}

// SetDueDate sets campaign due date.
func (c *Campaign) SetDueDate(d *time.Time) {
	c.dueDate = d
	c.updatedAt = time.Now()
}

// SetTags sets campaign tags.
func (c *Campaign) SetTags(tags []string) {
	c.tags = tags
	c.updatedAt = time.Now()
}

// SetCreatedBy sets the creator.
func (c *Campaign) SetCreatedBy(userID shared.ID) {
	c.createdBy = &userID
}

// CampaignSummary is what a campaign holds, derived from its tasks and their
// findings as one caller may see them: a restricted caller counts only the
// tasks with a finding in their scope and the findings in it; HiddenTasks is
// the count of the others.
type CampaignSummary struct {
	Tasks            int
	LiveTasks        int // open, in progress, verifying or on hold
	DoneTasks        int // done: every finding closed, at least one verified fixed
	OverdueTasks     int // live and past their deadline
	HiddenTasks      int
	Findings         int // primary findings of the visible tasks
	ClosedFindings   int
	VerifiedFindings int
}

// Progress is the share of the findings that are closed, in percent.
func (s CampaignSummary) Progress() float64 {
	if s.Findings == 0 {
		return 0
	}
	return float64(s.ClosedFindings) / float64(s.Findings) * 100
}

// IsDone reports a campaign whose work is finished: it has tasks, none is
// still live and at least one is done (an organization-wide summary). A
// campaign whose tasks were all canceled or closed without a verified fix
// fixed nothing.
func (s CampaignSummary) IsDone() bool {
	return s.Tasks > 0 && s.LiveTasks == 0 && s.DoneTasks > 0
}

// TryAutoComplete completes an active campaign whose (organization-wide)
// summary is done. Returns whether it changed.
func (c *Campaign) TryAutoComplete(s CampaignSummary) bool {
	if c.status != CampaignStatusActive || !s.IsDone() {
		return false
	}
	return c.Complete() == nil
}

// TryAutoReopen moves a completed campaign back to active when one of its
// tasks is live again (a regression task, a reopened task). Returns whether
// it changed.
func (c *Campaign) TryAutoReopen(s CampaignSummary) bool {
	if c.status != CampaignStatusCompleted || s.LiveTasks == 0 {
		return false
	}
	return c.Reopen() == nil
}

// TakesTasks reports whether tasks may be added to the campaign: a draft or
// an active one.
func (c *Campaign) TakesTasks() bool {
	return c.status == CampaignStatusDraft || c.status == CampaignStatusActive
}

// Activate starts a draft campaign.
func (c *Campaign) Activate() error {
	if c.status != CampaignStatusDraft {
		return fmt.Errorf("%w: cannot activate from %s", shared.ErrValidation, c.status)
	}
	c.status = CampaignStatusActive
	now := time.Now()
	if c.startDate == nil {
		c.startDate = &now
	}
	c.updatedAt = now
	return nil
}

// Reopen moves a completed campaign back to active (its work turned out not
// to be done) and clears the completion time.
func (c *Campaign) Reopen() error {
	if c.status != CampaignStatusCompleted {
		return fmt.Errorf("%w: cannot reopen from %s", shared.ErrValidation, c.status)
	}
	c.status = CampaignStatusActive
	c.completedAt = nil
	c.updatedAt = time.Now()
	return nil
}

// Complete transitions to completed.
func (c *Campaign) Complete() error {
	if c.status != CampaignStatusActive {
		return fmt.Errorf("%w: cannot complete from %s", shared.ErrValidation, c.status)
	}
	c.status = CampaignStatusCompleted
	now := time.Now()
	c.completedAt = &now
	c.updatedAt = now
	return nil
}

// Cancel transitions to canceled. Terminal states (completed, already
// canceled) cannot be canceled — mirrors the guards on the other transitions.
func (c *Campaign) Cancel() error {
	if c.status == CampaignStatusCompleted || c.status == CampaignStatusCanceled {
		return fmt.Errorf("%w: cannot cancel from %s", shared.ErrValidation, c.status)
	}
	c.status = CampaignStatusCanceled
	c.updatedAt = time.Now()
	return nil
}

// IsOverdue reports a campaign past the END of its due day (UTC) that is
// not completed or canceled. The due date is stored as a date, so it reads
// back as the start of that day; a campaign due today is not overdue today.
func (c *Campaign) IsOverdue() bool {
	return c.isOverdueAt(time.Now())
}

func (c *Campaign) isOverdueAt(now time.Time) bool {
	if c.dueDate == nil || c.status == CampaignStatusCompleted || c.status == CampaignStatusCanceled {
		return false
	}
	return !now.Before(DueDayEnd(*c.dueDate))
}

// DueDayEnd is the first instant after the due day (UTC): a campaign is
// overdue from then on.
func DueDayEnd(due time.Time) time.Time {
	d := due.UTC()
	return time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
}

// Errors
var (
	ErrCampaignNotFound = fmt.Errorf("%w: remediation campaign not found", shared.ErrNotFound)
	// ErrCampaignVersionConflict: the campaign changed since the caller read
	// it (another person, or the platform); reload and retry.
	// ErrCampaignNotDone refuses completing a campaign that still has a live
	// task or has no done task.
	ErrCampaignNotDone = fmt.Errorf("%w: the campaign is not done: every task must be closed and at least one done", shared.ErrValidation)
	// ErrCampaignTakesNoTasks refuses adding a task to a completed or
	// canceled campaign.
	ErrCampaignTakesNoTasks = fmt.Errorf("%w: tasks can be added only to a draft or active campaign", shared.ErrValidation)
	// ErrCampaignDeadlineOnlyTightens refuses moving a campaign's due date
	// later or clearing it.
	ErrCampaignDeadlineOnlyTightens = fmt.Errorf("%w: a campaign's due date can only move earlier", shared.ErrValidation)
	ErrCampaignVersionConflict      = fmt.Errorf("%w: the remediation campaign was changed by someone else; reload it and try again", shared.ErrConflict)
)

// CampaignViewer is who reads campaigns: the scope (nil = everything) and,
// for a restricted caller, the user whose own campaigns (created by or
// assigned to them) stay visible.
type CampaignViewer struct {
	Scope  *shared.DataScope
	UserID *shared.ID
}

// Restricted reports a viewer narrowed to scope rows.
func (v CampaignViewer) Restricted() bool { return v.Scope.Restricted() }

// CampaignFilter defines criteria for listing campaigns.
type CampaignFilter struct {
	TenantID *shared.ID
	Status   *CampaignStatus
	Priority *CampaignPriority
	Search   *string
	// Viewer limits the list to the campaigns the caller may see: a
	// restricted caller sees a campaign they created or own, or one with a
	// task that has a finding in their scope.
	Viewer CampaignViewer
}

// CampaignTaskRef is one task of a campaign, as an add or a move sees it.
type CampaignTaskRef struct {
	TaskID       shared.ID
	CampaignID   *shared.ID
	CampaignName string
}

// CampaignRepository defines persistence for remediation campaigns.
type CampaignRepository interface {
	Create(ctx context.Context, campaign *Campaign) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*Campaign, error)
	// Update saves every field when the stored version equals the
	// campaign's, bumps the version, and returns ErrCampaignVersionConflict
	// otherwise.
	Update(ctx context.Context, campaign *Campaign) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
	List(ctx context.Context, filter CampaignFilter, page pagination.Pagination) (pagination.Result[*Campaign], error)
	// CountByStatus counts the campaigns the viewer may see, per status.
	CountByStatus(ctx context.Context, tenantID shared.ID, viewer CampaignViewer) (map[CampaignStatus]int, error)
	// Visible reports whether the viewer may see the campaign.
	Visible(ctx context.Context, tenantID, id shared.ID, viewer CampaignViewer) (bool, error)
	// HasTaskOutsideScope reports whether a task of the campaign has a
	// finding outside the scope (nil scope: never).
	HasTaskOutsideScope(ctx context.Context, tenantID, id shared.ID, scope *shared.DataScope) (bool, error)
	// Summaries derives each campaign's summary from its tasks, counting the
	// findings in the scope only (nil scope: every finding).
	Summaries(ctx context.Context, tenantID shared.ID, ids []shared.ID, scope *shared.DataScope) (map[shared.ID]CampaignSummary, error)
	// TaskRefs returns the campaign of each of the tenant's tasks (unknown
	// ids are left out).
	TaskRefs(ctx context.Context, tenantID shared.ID, taskIDs []shared.ID) ([]CampaignTaskRef, error)
	// SetTasksCampaign puts the tasks in the campaign (nil: in none) with a
	// timeline entry on each task; it bumps each task's version. Returns the
	// tasks that changed.
	SetTasksCampaign(ctx context.Context, tenantID shared.ID, taskIDs []shared.ID, campaignID *shared.ID, actor *shared.ID) ([]shared.ID, error)
	// ListForReconcile returns active and completed campaigns across
	// tenants, least recently reconciled first, up to limit, and stamps
	// them reconciled.
	ListForReconcile(ctx context.Context, limit int) ([]*Campaign, error)
}
