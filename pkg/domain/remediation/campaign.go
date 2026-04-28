// Package remediation provides domain models for remediation campaign management.
package remediation

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
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
	id             shared.ID
	tenantID       shared.ID
	name           string
	description    string
	status         CampaignStatus
	priority       CampaignPriority
	findingFilter  map[string]any
	findingCount   int
	resolvedCount  int
	progress       float64
	riskBefore     *float64
	riskAfter      *float64
	riskReduction  *float64
	assignedTo     *shared.ID
	assignedTeam   *shared.ID
	startDate      *time.Time
	dueDate        *time.Time
	completedAt    *time.Time
	tags           []string
	createdBy      *shared.ID
	createdAt      time.Time
	updatedAt      time.Time
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
) *Campaign {
	return &Campaign{
		id: id, tenantID: tenantID,
		name: name, description: description,
		status: status, priority: priority,
		findingFilter: findingFilter,
		findingCount: findingCount, resolvedCount: resolvedCount, progress: progress,
		riskBefore: riskBefore, riskAfter: riskAfter, riskReduction: riskReduction,
		assignedTo: assignedTo, assignedTeam: assignedTeam,
		startDate: startDate, dueDate: dueDate, completedAt: completedAt,
		tags: tags, createdBy: createdBy,
		createdAt: createdAt, updatedAt: updatedAt,
	}
}

// Getters
func (c *Campaign) ID() shared.ID               { return c.id }
func (c *Campaign) TenantID() shared.ID          { return c.tenantID }
func (c *Campaign) Name() string                 { return c.name }
func (c *Campaign) Description() string           { return c.description }
func (c *Campaign) Status() CampaignStatus        { return c.status }
func (c *Campaign) Priority() CampaignPriority    { return c.priority }
func (c *Campaign) FindingFilter() map[string]any  { return c.findingFilter }
func (c *Campaign) FindingCount() int              { return c.findingCount }
func (c *Campaign) ResolvedCount() int             { return c.resolvedCount }
func (c *Campaign) Progress() float64              { return c.progress }
func (c *Campaign) RiskBefore() *float64           { return c.riskBefore }
func (c *Campaign) RiskAfter() *float64            { return c.riskAfter }
func (c *Campaign) RiskReduction() *float64        { return c.riskReduction }
func (c *Campaign) AssignedTo() *shared.ID         { return c.assignedTo }
func (c *Campaign) AssignedTeam() *shared.ID       { return c.assignedTeam }
func (c *Campaign) StartDate() *time.Time          { return c.startDate }
func (c *Campaign) DueDate() *time.Time            { return c.dueDate }
func (c *Campaign) CompletedAt() *time.Time        { return c.completedAt }
func (c *Campaign) Tags() []string                 { return c.tags }
func (c *Campaign) CreatedBy() *shared.ID          { return c.createdBy }
func (c *Campaign) CreatedAt() time.Time           { return c.createdAt }
func (c *Campaign) UpdatedAt() time.Time           { return c.updatedAt }

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
// is resolved (progress at 100%). A zero-finding campaign is NOT
// treated as complete — an empty campaign is a misconfiguration, not
// an accomplishment.
func (c *Campaign) AllFindingsResolved() bool {
	return c.findingCount > 0 && c.resolvedCount >= c.findingCount
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
	if !c.AllFindingsResolved() {
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

// RecordRiskReduction records risk before/after for this campaign.
func (c *Campaign) RecordRiskReduction(before, after float64) {
	c.riskBefore = &before
	c.riskAfter = &after
	reduction := before - after
	c.riskReduction = &reduction
	c.updatedAt = time.Now()
}

// Activate transitions to active status.
func (c *Campaign) Activate() error {
	if c.status != CampaignStatusDraft && c.status != CampaignStatusPaused {
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

// Cancel transitions to canceled.
func (c *Campaign) Cancel() {
	c.status = CampaignStatusCanceled
	c.updatedAt = time.Now()
}

// IsOverdue returns true if past due date and not completed.
func (c *Campaign) IsOverdue() bool {
	if c.dueDate == nil || c.status == CampaignStatusCompleted || c.status == CampaignStatusCanceled {
		return false
	}
	return time.Now().After(*c.dueDate)
}

// Errors
var (
	ErrCampaignNotFound = fmt.Errorf("%w: remediation campaign not found", shared.ErrNotFound)
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
	Update(ctx context.Context, campaign *Campaign) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
	List(ctx context.Context, filter CampaignFilter, page pagination.Pagination) (pagination.Result[*Campaign], error)
}
