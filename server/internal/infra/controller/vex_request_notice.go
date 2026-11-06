package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// VEXNoticeDispatcher sends the batched approver notices for false-positive
// requests VEX statements made (*finding.VulnerabilityService).
type VEXNoticeDispatcher interface {
	DispatchVEXRequestNotices(ctx context.Context) (int, error)
}

// VEXRequestNoticeController drains the VEX request notice outbox every
// minute, off the ingest path.
type VEXRequestNoticeController struct {
	dispatcher VEXNoticeDispatcher
	logger     *logger.Logger
}

// NewVEXRequestNoticeController creates the controller.
func NewVEXRequestNoticeController(d VEXNoticeDispatcher, log *logger.Logger) *VEXRequestNoticeController {
	if log == nil {
		log = logger.NewNop()
	}
	return &VEXRequestNoticeController{dispatcher: d, logger: log}
}

// Name implements Controller.
func (c *VEXRequestNoticeController) Name() string { return "vex-request-notice" }

// Interval implements Controller.
func (c *VEXRequestNoticeController) Interval() time.Duration { return time.Minute }

// Reconcile implements Controller.
func (c *VEXRequestNoticeController) Reconcile(ctx context.Context) (int, error) {
	n, err := c.dispatcher.DispatchVEXRequestNotices(ctx)
	if err != nil {
		c.logger.Error("vex request notices failed", "error", err)
		return n, err
	}
	if n > 0 {
		c.logger.Info("vex request notices sent", "requests", n)
	}
	return n, nil
}
