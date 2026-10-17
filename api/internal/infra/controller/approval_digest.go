package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// ApprovalDigestSender sends the daily digest of finding requests to each
// approver, at most once a day each (*finding.VulnerabilityService).
type ApprovalDigestSender interface {
	SendApprovalDigests(ctx context.Context) (int, error)
}

// ApprovalDigestController runs the approver digest every hour; the sender
// itself keeps it to one per approver per day.
type ApprovalDigestController struct {
	sender ApprovalDigestSender
	logger *logger.Logger
}

// NewApprovalDigestController creates the controller.
func NewApprovalDigestController(sender ApprovalDigestSender, log *logger.Logger) *ApprovalDigestController {
	if log == nil {
		log = logger.NewNop()
	}
	return &ApprovalDigestController{sender: sender, logger: log}
}

// Name implements Controller.
func (c *ApprovalDigestController) Name() string { return "approval-digest" }

// Interval implements Controller.
func (c *ApprovalDigestController) Interval() time.Duration { return time.Hour }

// Reconcile implements Controller.
func (c *ApprovalDigestController) Reconcile(ctx context.Context) (int, error) {
	n, err := c.sender.SendApprovalDigests(ctx)
	if err != nil {
		c.logger.Error("approval digest failed", "error", err)
		return n, err
	}
	if n > 0 {
		c.logger.Info("approval digests sent", "count", n)
	}
	return n, nil
}
