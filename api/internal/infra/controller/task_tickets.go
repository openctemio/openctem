package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// taskIssueSyncer pushes one task's state to its tracker issue
// (*jira.SyncService).
type taskIssueSyncer interface {
	SyncTaskIssue(ctx context.Context, tenantID, taskID shared.ID) error
}

// taskLinksBehind lists task links whose task moved since the last push.
type taskLinksBehind interface {
	TaskLinksBehindForPlatform(ctx context.Context, limit int) ([]ticketlink.TaskLinkRef, error)
}

// TaskTicketBatch bounds how many task issues one pass pushes (the tracker's
// rate limit is shared with every other call of the integration).
const TaskTicketBatch = 100

// TaskTicketController keeps the issues of remediation tasks in step with
// the tasks: every pass pushes the tasks whose state differs from the state
// last pushed to their issue (a missed or failed push is retried on the next
// pass). Each task is pushed in its own tenant.
type TaskTicketController struct {
	links    taskLinksBehind
	syncer   taskIssueSyncer
	interval time.Duration
	logger   *logger.Logger
}

// NewTaskTicketController creates the controller. A non-positive interval
// falls back to one minute.
func NewTaskTicketController(links taskLinksBehind, syncer taskIssueSyncer, interval time.Duration, log *logger.Logger) *TaskTicketController {
	if interval <= 0 {
		interval = time.Minute
	}
	return &TaskTicketController{links: links, syncer: syncer, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *TaskTicketController) Name() string { return "task-tickets" }

// Interval returns how often the pass runs.
func (c *TaskTicketController) Interval() time.Duration { return c.interval }

// Reconcile pushes the task issues that are behind.
func (c *TaskTicketController) Reconcile(ctx context.Context) (int, error) {
	refs, err := c.links.TaskLinksBehindForPlatform(ctx, TaskTicketBatch)
	if err != nil {
		return 0, err
	}
	n, failed := 0, 0
	for _, r := range refs {
		if ctx.Err() != nil {
			break
		}
		if err := c.syncer.SyncTaskIssue(ctx, r.TenantID, r.TaskID); err != nil {
			if c.logger != nil {
				c.logger.Warn("task issue push failed; retried next pass", "tenant_id", r.TenantID.String(), "task_id", r.TaskID.String(), "error", logger.SanitizeError(err))
			}
			failed++
			continue
		}
		n++
	}
	if failed > 0 {
		// The pushes that worked still count; the error (without the
		// per-task detail, which is logged above) reaches the reconcile
		// metrics so a tracker outage is visible.
		return n, fmt.Errorf("%d of %d task issue pushes failed; retried next pass", failed, len(refs))
	}
	return n, nil
}
