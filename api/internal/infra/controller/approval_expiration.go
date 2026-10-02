package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
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

// ApprovalExpirationController auto-reopens findings whose risk acceptances have expired.
// It scans for approved approvals with an expires_at in the past, marks them as expired,
// and transitions the associated findings back to "confirmed" status.
type ApprovalExpirationController struct {
	approvalRepo vulnerability.ApprovalRepository
	findingRepo  vulnerability.FindingRepository
	config       *ApprovalExpirationControllerConfig
	logger       *logger.Logger
}

// NewApprovalExpirationController creates a new ApprovalExpirationController.
func NewApprovalExpirationController(
	approvalRepo vulnerability.ApprovalRepository,
	findingRepo vulnerability.FindingRepository,
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
		approvalRepo: approvalRepo,
		findingRepo:  findingRepo,
		config:       config,
		logger:       config.Logger,
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

// Reconcile finds expired approved approvals and reopens associated findings.
func (c *ApprovalExpirationController) Reconcile(ctx context.Context) (int, error) {
	expired, err := c.approvalRepo.ListExpiredApproved(ctx, c.config.BatchSize)
	if err != nil {
		c.logger.Error("failed to list expired approvals", "error", err)
		return 0, err
	}

	if len(expired) == 0 {
		return 0, nil
	}

	c.logger.Info("found expired approved approvals", "count", len(expired))

	processed := 0
	for _, approval := range expired {
		if err := c.processExpiredApproval(ctx, approval); err != nil {
			c.logger.Error("failed to process expired approval",
				"approval_id", approval.ID,
				"finding_id", approval.FindingID,
				"tenant_id", approval.TenantID,
				"error", err,
			)
			continue
		}
		processed++
	}

	if processed > 0 {
		c.logger.Info("processed expired approvals",
			"processed", processed,
			"total", len(expired),
		)
	}

	return processed, nil
}

// processExpiredApproval handles a single expired approval:
// 1. Mark the approval status as canceled (expired)
// 2. Transition the finding back to "confirmed"
func (c *ApprovalExpirationController) processExpiredApproval(ctx context.Context, approval *vulnerability.Approval) error {
	// Step 1: Mark approval as expired
	if err := approval.Expire(); err != nil {
		// Approval may no longer be in approved state (race condition)
		if errors.Is(err, shared.ErrValidation) {
			c.logger.Debug("approval no longer expirable, skipping",
				"approval_id", approval.ID,
				"status", approval.Status,
			)
			return nil
		}
		return err
	}

	if err := c.approvalRepo.Update(ctx, approval); err != nil {
		if errors.Is(err, vulnerability.ErrConcurrentModification) {
			c.logger.Debug("approval concurrently modified, skipping",
				"approval_id", approval.ID,
			)
			return nil
		}
		return fmt.Errorf("failed to update approval: %w", err)
	}

	// Step 2: Reopen the finding to "confirmed" status
	findingIDs := []shared.ID{approval.FindingID}
	err := c.findingRepo.UpdateStatusBatch(
		ctx,
		approval.TenantID,
		findingIDs,
		vulnerability.FindingStatusConfirmed,
		"auto_reopened_expired_acceptance",
		nil, // no resolvedBy — system action
	)
	if err != nil {
		return fmt.Errorf("failed to reopen finding: %w", err)
	}

	c.logger.Info("reopened finding due to expired risk acceptance",
		"finding_id", approval.FindingID,
		"approval_id", approval.ID,
		"tenant_id", approval.TenantID,
		"expired_at", approval.ExpiresAt,
	)

	return nil
}
