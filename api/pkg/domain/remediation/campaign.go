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
	CampaignStatusDraft      CampaignStatus = "draft"
	CampaignStatusActive     CampaignStatus = "active"
	CampaignStatusPaused     CampaignStatus = "paused"
	CampaignStatusValidating CampaignStatus = "validating"
	CampaignStatusCompleted  CampaignStatus = "completed"
	CampaignStatusCanceled   CampaignStatus = "canceled"
)

// CampaignPriority defines urgency levels.
type CampaignPriority string

const (
	CampaignPriorityCritical CampaignPriority = "critical"
	CampaignPriorityHigh     CampaignPriority = "high"
	CampaignPriorityMedium   CampaignPriority = "medium"
	CampaignPriorityLow      CampaignPriority = "low"
)

// Campaign tracks a remediation effort across multiple findings.
type Campaign struct {
	id            shared.ID
	tenantID      shared.ID
	name          string
	description   string
	status        CampaignStatus
	priority      CampaignPriority
	findingFilter map[string]any
	findingCount  int
	resolvedCount int
	progress      float64
	riskBefore    *float64
	riskAfter     *float64
	riskReduction *float64
	assignedTo    *shared.ID
	assignedTeam  *shared.ID
	startDate     *time.Time
	dueDate       *time.Time
	completedAt   *time.Time
	tags          []string
	createdBy     *shared.ID
	createdAt     time.Time
	updatedAt     time.Time
	// version is the optimistic-concurrency token: every full save checks it
	// and bumps it (CampaignRepository.Update).
	version int
	// verifiedCount: members closed as resolved (a verified fix), computed
	// with the counts and never stored. Accepted, false-positive and
	// duplicate members are closed but not fixed.
	verifiedCount int
}

// NewCampaign creates a new remediation campaign.
func NewCampaign(tenantID shared.ID, name string, priority CampaignPriority) (*Campaign, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	now := time.Now()
	return &Campaign{
		id:            shared.NewID(),
		tenantID:      tenantID,
		name:          name,
		status:        CampaignStatusDraft,
		priority:      priority,
		findingFilter: map[string]any{},
		tags:          []string{},
		createdAt:     now,
		updatedAt:     now,
		version:       1,
	}, nil
}

// ReconstituteCampaign creates from persisted data.
func ReconstituteCampaign(
	id, tenantID shared.ID,
	name, description string,
	status CampaignStatus, priority CampaignPriority,
	findingFilter map[string]any,
	findingCount, resolvedCount int, progress float64,
	riskBefore, riskAfter, riskReduction *float64,
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
		findingFilter: findingFilter,
		findingCount:  findingCount, resolvedCount: resolvedCount, progress: progress,
		riskBefore: riskBefore, riskAfter: riskAfter, riskReduction: riskReduction,
		assignedTo: assignedTo, assignedTeam: assignedTeam,
		startDate: startDate, dueDate: dueDate, completedAt: completedAt,
		tags: tags, createdBy: createdBy,
		createdAt: createdAt, updatedAt: updatedAt,
		version: version,
	}
}

// Getters
func (c *Campaign) ID() shared.ID                 { return c.id }
func (c *Campaign) TenantID() shared.ID           { return c.tenantID }
func (c *Campaign) Name() string                  { return c.name }
func (c *Campaign) Description() string           { return c.description }
func (c *Campaign) Status() CampaignStatus        { return c.status }
func (c *Campaign) Priority() CampaignPriority    { return c.priority }
func (c *Campaign) FindingFilter() map[string]any { return c.findingFilter }
func (c *Campaign) FindingCount() int             { return c.findingCount }
func (c *Campaign) ResolvedCount() int            { return c.resolvedCount }
func (c *Campaign) Progress() float64             { return c.progress }
func (c *Campaign) RiskBefore() *float64          { return c.riskBefore }
func (c *Campaign) RiskAfter() *float64           { return c.riskAfter }
func (c *Campaign) RiskReduction() *float64       { return c.riskReduction }
func (c *Campaign) AssignedTo() *shared.ID        { return c.assignedTo }
func (c *Campaign) AssignedTeam() *shared.ID      { return c.assignedTeam }
func (c *Campaign) StartDate() *time.Time         { return c.startDate }
func (c *Campaign) DueDate() *time.Time           { return c.dueDate }
func (c *Campaign) CompletedAt() *time.Time       { return c.completedAt }
func (c *Campaign) Tags() []string                { return c.tags }
func (c *Campaign) CreatedBy() *shared.ID         { return c.createdBy }
func (c *Campaign) CreatedAt() time.Time          { return c.createdAt }
func (c *Campaign) UpdatedAt() time.Time          { return c.updatedAt }
func (c *Campaign) Version() int                  { return c.version }
func (c *Campaign) VerifiedCount() int            { return c.verifiedCount }

// SetVerifiedCount records how many members are verified fixed (resolved).
func (c *Campaign) SetVerifiedCount(n int) { c.verifiedCount = n }

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

// SetFindingFilter sets the filter criteria for this campaign's findings.
func (c *Campaign) SetFindingFilter(filter map[string]any) {
	c.findingFilter = filter
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

// UpdateProgress updates finding counts and progress percentage.
func (c *Campaign) UpdateProgress(findingCount, resolvedCount int) {
	c.findingCount = findingCount
	c.resolvedCount = resolvedCount
	if findingCount > 0 {
		c.progress = float64(resolvedCount) / float64(findingCount) * 100
	} else {
		c.progress = 0
	}
	c.updatedAt = time.Now()
}

// AllFindingsResolved reports whether every finding in the campaign
// is closed (progress at 100%). A zero-finding campaign is NOT
// treated as complete — an empty campaign is a misconfiguration, not
// an accomplishment.
func (c *Campaign) AllFindingsResolved() bool {
	return c.findingCount > 0 && c.resolvedCount >= c.findingCount
}

// IsDone reports a campaign whose work is really finished: every member is
// closed AND at least one was verified fixed. A campaign whose members were
// all accepted, marked false positive or folded as duplicates fixed nothing.
func (c *Campaign) IsDone() bool {
	return c.AllFindingsResolved() && c.verifiedCount > 0
}

// TryAutoComplete attempts the active/validating → completed
// transition when all findings are resolved. this is what
// turns "every finding in my campaign hit resolved" into an actual
// campaign-level event without an operator clicking Complete.
//
// Returns (true, nil) on successful auto-complete.
// Returns (false, nil) when not yet eligible — callers should treat
// this as a normal no-op, not an error.
// Returns (_, err) for genuine state-machine or validation failures.
func (c *Campaign) TryAutoComplete() (bool, error) {
	if !c.IsDone() {
		return false, nil
	}
	// Eligible terminal targets: active and validating. Draft,
	// paused, completed, canceled are explicit user states that we
	// do not auto-complete out of.
	if c.status != CampaignStatusActive && c.status != CampaignStatusValidating {
		return false, nil
	}
	if err := c.Complete(); err != nil {
		return false, err
	}
	return true, nil
}

// Activate transitions to active status. Allowed from draft (first start),
// paused (resume) and validating (validation failed: the fix did not hold,
// so the campaign goes back to remediation instead of being completed).
func (c *Campaign) Activate() error {
	if c.status != CampaignStatusDraft && c.status != CampaignStatusPaused &&
		c.status != CampaignStatusValidating {
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

// Pause transitions to paused.
func (c *Campaign) Pause() error {
	if c.status != CampaignStatusActive {
		return fmt.Errorf("%w: cannot pause from %s", shared.ErrValidation, c.status)
	}
	c.status = CampaignStatusPaused
	c.updatedAt = time.Now()
	return nil
}

// StartValidation transitions to validating (re-scanning to verify fixes).
func (c *Campaign) StartValidation() error {
	if c.status != CampaignStatusActive {
		return fmt.Errorf("%w: cannot validate from %s", shared.ErrValidation, c.status)
	}
	c.status = CampaignStatusValidating
	c.updatedAt = time.Now()
	return nil
}

// Complete transitions to completed.
func (c *Campaign) Complete() error {
	if c.status != CampaignStatusActive && c.status != CampaignStatusValidating {
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
	// ErrCampaignNotDone refuses completing a campaign whose findings are not
	// all closed or of which none was verified fixed, unless the person
	// explicitly closes it with open members.
	ErrCampaignNotDone = fmt.Errorf("%w: the campaign is not done (every finding closed and at least one verified fixed); set close_with_open_members to complete it anyway", shared.ErrValidation)
	// ErrCampaignDeadlineOnlyTightens refuses moving a campaign's due date
	// later or clearing it.
	ErrCampaignDeadlineOnlyTightens = fmt.Errorf("%w: a campaign's due date can only move earlier", shared.ErrValidation)
	ErrCampaignVersionConflict      = fmt.Errorf("%w: the remediation campaign was changed by someone else; reload it and try again", shared.ErrConflict)
)

// CampaignFilter defines criteria for listing campaigns.
type CampaignFilter struct {
	TenantID *shared.ID
	Status   *CampaignStatus
	Priority *CampaignPriority
	Search   *string
}

// CampaignRepository defines persistence for remediation campaigns.
type CampaignRepository interface {
	Create(ctx context.Context, campaign *Campaign) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*Campaign, error)
	// Update saves every field when the stored version equals the
	// campaign's, bumps the version, and returns ErrCampaignVersionConflict
	// otherwise.
	Update(ctx context.Context, campaign *Campaign) error
	// UpdateCounts writes only the finding counters and progress and stamps
	// last_reconciled_at. It never touches status, dates or the version, so a
	// counter refresh cannot undo a person's change.
	UpdateCounts(ctx context.Context, campaign *Campaign) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
	List(ctx context.Context, filter CampaignFilter, page pagination.Pagination) (pagination.Result[*Campaign], error)

	// ListNonTerminal returns campaigns that are not in a terminal state
	// (completed/canceled) across all tenants, least recently reconciled
	// first (never reconciled first), up to limit. Used by the progress-reconcile controller
	// to refresh finding counts and auto-complete. limit <= 0 means a
	// repository-chosen default.
	ListNonTerminal(ctx context.Context, limit int) ([]*Campaign, error)
}
