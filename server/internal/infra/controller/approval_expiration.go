package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ApprovalExpirationControllerConfig configures the ApprovalExpirationController.
type ApprovalExpirationControllerConfig struct {
	// Interval is how often to run the expiration check.
	// Default: 1 hour.
	Interval time.Duration

	// BatchSize is the maximum number of expired approvals to process per reconciliation.
	// Default: 100.
	BatchSize int

	// Logger for logging.
	Logger *logger.Logger
}

// AcceptanceExpiryStore ends accepted risks whose acceptance end has passed,
// each in one transaction (finding, approval, timeline, SLA clock).
// Implemented by *postgres.FindingAcceptanceExpiryRepository.
type AcceptanceExpiryStore interface {
	ListDue(ctx context.Context, limit int) ([]vulnerability.AcceptanceDue, error)
	Expire(ctx context.Context, due vulnerability.AcceptanceDue, newDeadline *time.Time, now time.Time) (bool, error)
	ExpireStaleRequests(ctx context.Context) (int64, error)
}

// OverdueRequestStore expires pending requests nobody decided by their
// decide-by time (*postgres.FindingApprovalRepository).
type OverdueRequestStore interface {
	ExpireOverdueRequests(ctx context.Context) (int64, error)
}

// SLADeadlineCalculator computes a finding's SLA deadline from a start time
// with the tenant's policy. Implemented by *sla.Service.
type SLADeadlineCalculator interface {
	CalculateSLADeadlineForPriority(ctx context.Context, tenantID, assetID, priorityClass string,
		severity vulnerability.Severity, detectedAt time.Time) (time.Time, error)
}

// ApprovalExpirationController ends risk acceptances whose end has passed.
//
// A finding is the unit: every accepted finding whose acceptance_expires_at
// has passed returns to confirmed, with a new SLA clock from the reopen and
// its approved acceptance requests marked expired, in one transaction with
// its timeline entries (AcceptanceExpiryStore.Expire). A failure leaves
// nothing half done, and the next run retries it. Approved requests whose
// end passed while the finding had already moved on (or holds a newer
// acceptance) are only marked expired.
type ApprovalExpirationController struct {
	store   AcceptanceExpiryStore
	overdue OverdueRequestStore
	sla     SLADeadlineCalculator
	now     func() time.Time
	config  *ApprovalExpirationControllerConfig
	logger  *logger.Logger
}

// NewApprovalExpirationController creates a new ApprovalExpirationController.
// sla may be nil (no new SLA clock is computed then).
func NewApprovalExpirationController(
	store AcceptanceExpiryStore,
	sla SLADeadlineCalculator,
	config *ApprovalExpirationControllerConfig,
) *ApprovalExpirationController {
	if config == nil {
		config = &ApprovalExpirationControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 1 * time.Hour
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}

	return &ApprovalExpirationController{
		store:  store,
		sla:    sla,
		now:    time.Now,
		config: config,
		logger: config.Logger,
	}
}

// Name returns the controller name.
func (c *ApprovalExpirationController) Name() string {
	return "approval-expiration"
}

// Interval returns the reconciliation interval.
func (c *ApprovalExpirationController) Interval() time.Duration {
	return c.config.Interval
}

// Reconcile ends the acceptances that are due, then marks the remaining
// approved requests whose end has passed as expired. Returns how many
// findings were reopened.
func (c *ApprovalExpirationController) Reconcile(ctx context.Context) (int, error) {
	due, err := c.store.ListDue(ctx, c.config.BatchSize)
	if err != nil {
		c.logger.Error("failed to list ended acceptances", "error", err)
		return 0, err
	}
	reopened := 0
	for _, d := range due {
		now := c.now().UTC()
		ok, err := c.store.Expire(ctx, d, c.newDeadline(ctx, d, now), now)
		if err != nil {
			c.logger.Error("failed to end acceptance", "finding_id", d.FindingID, "tenant_id", d.TenantID, "error", err)
			continue
		}
		if ok {
			reopened++
			c.logger.Info("reopened finding: risk acceptance ended",
				"finding_id", d.FindingID, "tenant_id", d.TenantID, "expired_at", d.ExpiresAt)
		}
	}

	if err := c.expireStaleApprovals(ctx); err != nil {
		return reopened, err
	}
	if c.overdue != nil {
		n, err := c.overdue.ExpireOverdueRequests(ctx)
		if err != nil {
			c.logger.Error("failed to expire overdue approval requests", "error", err)
			return reopened, err
		}
		if n > 0 {
			c.logger.Info("expired approval requests past their decide-by time", "count", n)
		}
	}
	return reopened, nil
}

// SetOverdueRequests wires the expiry of pending requests past their
// decide-by time. Nil leaves pending requests alone.
func (c *ApprovalExpirationController) SetOverdueRequests(s OverdueRequestStore) {
	c.overdue = s
}

// newDeadline is the SLA deadline of a new clock started at now (owner
// decision D3: an expired acceptance starts a new SLA clock), or nil when the
// finding has no SLA or the policy cannot be read (the reopen still happens).
func (c *ApprovalExpirationController) newDeadline(ctx context.Context, d vulnerability.AcceptanceDue, now time.Time) *time.Time {
	if c.sla == nil {
		return nil
	}
	sev, err := vulnerability.ParseSeverity(d.Severity)
	if err != nil {
		sev = vulnerability.SeverityMedium
	}
	assetID := ""
	if !d.AssetID.IsZero() {
		assetID = d.AssetID.String()
	}
	deadline, err := c.sla.CalculateSLADeadlineForPriority(ctx, d.TenantID.String(), assetID, d.PriorityClass, sev, now)
	if err != nil {
		c.logger.Warn("acceptance expiry: SLA deadline not computed", "finding_id", d.FindingID, "error", err)
		return nil
	}
	if deadline.IsZero() {
		return nil
	}
	return &deadline
}

// expireStaleApprovals marks approved requests whose end has passed as
// expired when their finding was not an ended acceptance (it moved on, or
// holds a newer acceptance). A finding whose end failed above keeps its
// request approved, so the next run ends both together.
func (c *ApprovalExpirationController) expireStaleApprovals(ctx context.Context) error {
	if _, err := c.store.ExpireStaleRequests(ctx); err != nil {
		c.logger.Error("failed to expire stale acceptance requests", "error", err)
		return err
	}
	return nil
}
