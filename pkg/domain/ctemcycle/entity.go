package ctemcycle

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// CycleStatus represents the lifecycle status of a CTEM cycle.
type CycleStatus string

const (
	CycleStatusPlanning CycleStatus = "planning"
	CycleStatusActive   CycleStatus = "active"
	CycleStatusReview   CycleStatus = "review"
	CycleStatusClosed   CycleStatus = "closed"
)

// Charter holds the business context for a CTEM cycle.
type Charter struct {
	BusinessPriorities []string `json:"business_priorities"`
	RiskAppetite       string   `json:"risk_appetite"`
	InScopeServices    []string `json:"in_scope_services"`
	Objectives         []string `json:"objectives"`
}

// CycleMetric holds a computed metric for a cycle.
type CycleMetric struct {
	MetricType string
	Value      float64
	ComputedAt time.Time
}

// Cycle represents a CTEM assessment cycle.
type Cycle struct {
	id        shared.ID
	tenantID  shared.ID
	name      string
	status    CycleStatus
	startDate *time.Time
	endDate   *time.Time
	charter   Charter
	closedBy  *shared.ID
	closedAt  *time.Time
	createdBy shared.ID
	createdAt time.Time
	updatedAt time.Time
}

// CycleData is the persistence representation.
type CycleData struct {
	ID        shared.ID
	TenantID  shared.ID
	Name      string
	Status    CycleStatus
	StartDate *time.Time
	EndDate   *time.Time
	Charter   Charter
	ClosedBy  *shared.ID
	ClosedAt  *time.Time
	CreatedBy shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewCycle creates a new CTEM cycle in planning status.
func NewCycle(tenantID shared.ID, name string, createdBy shared.ID) (*Cycle, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}

	now := time.Now()
	return &Cycle{
		id:        shared.NewID(),
		tenantID:  tenantID,
		name:      name,
		status:    CycleStatusPlanning,
		createdBy: createdBy,
		createdAt: now,
		updatedAt: now,
	}, nil
}

// ReconstituteCycle recreates from persistence.
func ReconstituteCycle(data CycleData) *Cycle {
	return &Cycle{
		id:        data.ID,
		tenantID:  data.TenantID,
		name:      data.Name,
		status:    data.Status,
		startDate: data.StartDate,
		endDate:   data.EndDate,
		charter:   data.Charter,
		closedBy:  data.ClosedBy,
		closedAt:  data.ClosedAt,
		createdBy: data.CreatedBy,
		createdAt: data.CreatedAt,
		updatedAt: data.UpdatedAt,
	}
}

// Getters
func (c *Cycle) ID() shared.ID       { return c.id }
func (c *Cycle) TenantID() shared.ID  { return c.tenantID }
func (c *Cycle) Name() string         { return c.name }
func (c *Cycle) Status() CycleStatus  { return c.status }
func (c *Cycle) StartDate() *time.Time { return c.startDate }
func (c *Cycle) EndDate() *time.Time  { return c.endDate }
func (c *Cycle) Charter() Charter     { return c.charter }
func (c *Cycle) CreatedBy() shared.ID { return c.createdBy }
func (c *Cycle) CreatedAt() time.Time { return c.createdAt }

// SetCharter updates the cycle charter (only in planning status).
func (c *Cycle) SetCharter(charter Charter) error {
	if c.status != CycleStatusPlanning {
		return fmt.Errorf("%w: can only update charter in planning status", shared.ErrValidation)
	}
	c.charter = charter
	c.updatedAt = time.Now()
	return nil
}

// SetDates sets the cycle start/end dates.
func (c *Cycle) SetDates(start, end time.Time) error {
	if end.Before(start) {
		return fmt.Errorf("%w: end date must be after start date", shared.ErrValidation)
	}
	c.startDate = &start
	c.endDate = &end
	c.updatedAt = time.Now()
	return nil
}

// Activate transitions from planning to active.
// This should trigger scope snapshot creation externally.
func (c *Cycle) Activate() error {
	if c.status != CycleStatusPlanning {
		return fmt.Errorf("%w: can only activate from planning (current: %s)", shared.ErrValidation, c.status)
	}
	c.status = CycleStatusActive
	now := time.Now()
	if c.startDate == nil {
		c.startDate = &now
	}
	c.updatedAt = now
	return nil
}

// StartReview transitions from active to review.
func (c *Cycle) StartReview() error {
	if c.status != CycleStatusActive {
		return fmt.Errorf("%w: can only start review from active (current: %s)", shared.ErrValidation, c.status)
	}
	c.status = CycleStatusReview
	c.updatedAt = time.Now()
	return nil
}

// Close transitions from review to closed.
// Metrics should be computed externally and stored in ctem_cycle_metrics.
func (c *Cycle) Close(closedBy shared.ID) error {
	if c.status != CycleStatusReview {
		return fmt.Errorf("%w: can only close from review (current: %s)", shared.ErrValidation, c.status)
	}
	c.status = CycleStatusClosed
	c.closedBy = &closedBy
	now := time.Now()
	c.closedAt = &now
	if c.endDate == nil {
		c.endDate = &now
	}
	c.updatedAt = now
	return nil
}

// IsActive returns true if the cycle is in active status.
func (c *Cycle) IsActive() bool { return c.status == CycleStatusActive }
