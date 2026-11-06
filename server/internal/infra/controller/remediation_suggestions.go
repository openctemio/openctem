package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// remediationSuggestionRunner is the slice of *remediation.SuggestionService
// this controller drives.
type remediationSuggestionRunner interface {
	RunAll(ctx context.Context) (int, error)
}

// RemediationSuggestionController runs the remediation suggestion generator
// for every tenant with keyed findings and sends the daily digests
// (docs/rfcs/RFC-098-remediation-tasks.md §5). It only proposes.
type RemediationSuggestionController struct {
	svc      remediationSuggestionRunner
	interval time.Duration
	logger   *logger.Logger
}

// NewRemediationSuggestionController creates the controller. A non-positive
// interval falls back to 15 minutes.
func NewRemediationSuggestionController(svc remediationSuggestionRunner, interval time.Duration, log *logger.Logger) *RemediationSuggestionController {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	return &RemediationSuggestionController{svc: svc, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *RemediationSuggestionController) Name() string { return "remediation-suggestions" }

// Interval returns how often the generator runs.
func (c *RemediationSuggestionController) Interval() time.Duration { return c.interval }

// Reconcile runs the generator.
func (c *RemediationSuggestionController) Reconcile(ctx context.Context) (int, error) {
	n, err := c.svc.RunAll(ctx)
	if err != nil {
		return n, err
	}
	if n > 0 && c.logger != nil {
		c.logger.Debug("remediation suggestions generated", "tenants", n)
	}
	return n, nil
}
