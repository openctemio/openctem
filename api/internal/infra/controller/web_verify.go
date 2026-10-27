package controller

import (
	"context"
	"time"
)

// WebVerifyRunner runs one pass of the web verification planner.
type WebVerifyRunner interface {
	RunAll(ctx context.Context) (int, error)
}

// WebVerifyController schedules the verification of new or changed
// sensitive web paths on one replica at a time.
type WebVerifyController struct {
	runner   WebVerifyRunner
	interval time.Duration
}

// NewWebVerifyController creates the controller (interval default 15m).
func NewWebVerifyController(runner WebVerifyRunner, interval time.Duration) *WebVerifyController {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	return &WebVerifyController{runner: runner, interval: interval}
}

// Name returns the controller name.
func (c *WebVerifyController) Name() string { return "web-verify" }

// Interval returns how often the controller runs.
func (c *WebVerifyController) Interval() time.Duration { return c.interval }

// Exclusive: one replica plans at a time.
func (c *WebVerifyController) Exclusive() bool { return true }

// Reconcile runs one pass.
func (c *WebVerifyController) Reconcile(ctx context.Context) (int, error) {
	return c.runner.RunAll(ctx)
}
