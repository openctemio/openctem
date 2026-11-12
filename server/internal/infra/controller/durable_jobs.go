package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/durablejob"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Durable jobs (api/docs/architecture/durable-jobs.md): rows queued in the
// transaction of the change that needs them, claimed with FOR UPDATE SKIP
// LOCKED, so every replica may run this controller; a job runs on one.

const (
	durableJobBatch       = 50
	durableJobLease       = 2 * time.Minute
	durableJobRunTimeout  = time.Minute
	durableJobMaxAttempts = 8
	durableJobBaseBackoff = 30 * time.Second
	durableJobMaxBackoff  = time.Hour
)

// DurableJobHandler runs one job. An error that reports Permanent() true is
// not retried.
type DurableJobHandler func(ctx context.Context, j durablejob.Claimed) error

// DurableJobsController runs due durable jobs.
type DurableJobsController struct {
	store    durablejob.Store
	handlers map[durablejob.Kind]DurableJobHandler
	interval time.Duration
	logger   *logger.Logger
	now      func() time.Time
}

// NewDurableJobsController creates the controller. Only kinds with a handler
// are claimed: a replica without SMTP leaves invitation e-mails to one with
// it, and they wait rather than fail.
func NewDurableJobsController(store durablejob.Store, handlers map[durablejob.Kind]DurableJobHandler, interval time.Duration, log *logger.Logger) *DurableJobsController {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &DurableJobsController{store: store, handlers: handlers, interval: interval, logger: log, now: time.Now}
}

// Name returns the controller name.
func (c *DurableJobsController) Name() string { return "durable-jobs" }

// Interval returns how often due jobs are claimed.
func (c *DurableJobsController) Interval() time.Duration { return c.interval }

// Reconcile claims a batch of due jobs and runs them.
func (c *DurableJobsController) Reconcile(ctx context.Context) (int, error) {
	kinds := make([]durablejob.Kind, 0, len(c.handlers))
	for k := range c.handlers {
		kinds = append(kinds, k)
	}
	slices.Sort(kinds)
	jobs, err := c.store.Claim(ctx, kinds, durableJobBatch, durableJobLease)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, j := range jobs {
		if ctx.Err() != nil {
			// Unfinished jobs are claimed again once their lease passes.
			return done, ctx.Err()
		}
		if c.run(ctx, j) {
			done++
		}
	}
	return done, nil
}

// run runs one job and records the outcome; true when it completed.
func (c *DurableJobsController) run(ctx context.Context, j durablejob.Claimed) bool {
	runCtx, cancel := context.WithTimeout(ctx, durableJobRunTimeout)
	err := c.handlers[j.Kind](runCtx, j)
	cancel()
	log := c.logger.With("job_id", j.ID.String(), "kind", string(j.Kind), "tenant_id", j.TenantID.String(), "attempt", j.Attempts)
	if err == nil {
		if cerr := c.store.Complete(ctx, j); cerr != nil {
			// The job ran; it runs again when its lease passes. Handlers are
			// idempotent (a status push) or at-least-once (an e-mail).
			log.Error("durable job ran but could not be completed", "error", cerr)
		}
		return true
	}
	var perm interface{ Permanent() bool }
	if (errors.As(err, &perm) && perm.Permanent()) || j.Attempts >= durableJobMaxAttempts {
		log.Error("durable job given up", "error", err)
		if berr := c.store.Bury(ctx, j, err.Error()); berr != nil {
			log.Error("durable job could not be marked dead", "error", berr)
		}
		return false
	}
	at := c.now().Add(durableJobBackoff(j.Attempts))
	log.Warn("durable job failed, retrying", "error", err, "next_attempt_at", at)
	if rerr := c.store.Retry(ctx, j, at, err.Error()); rerr != nil {
		log.Error("durable job could not be rescheduled", "error", rerr)
	}
	return false
}

// durableJobBackoff is 30 s doubled per attempt, at most an hour.
func durableJobBackoff(attempts int) time.Duration {
	d := durableJobBaseBackoff
	for i := 1; i < attempts && d < durableJobMaxBackoff; i++ {
		d *= 2
	}
	return min(d, durableJobMaxBackoff)
}

// String helps logs and tests.
func (c *DurableJobsController) String() string {
	return fmt.Sprintf("durable-jobs(%d kinds)", len(c.handlers))
}
