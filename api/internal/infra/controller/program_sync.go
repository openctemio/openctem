package controller

import (
	"context"
	"time"
)

// ProgramSyncer syncs the programs whose scope comes from a source
// (*bountyprogram.Service).
type ProgramSyncer interface {
	SyncDue(ctx context.Context, interval time.Duration, limit int) (int, error)
}

// programSyncBatch bounds one reconcile (the next one takes the rest).
const programSyncBatch = 50

// ProgramSyncController reads the scope of every program with a source
// (the researcher API of its platform or a scope file it publishes) every
// 6 hours (RFC-065 §14). Removals apply at once; additions wait for a member.
type ProgramSyncController struct {
	programs ProgramSyncer
	interval time.Duration
}

// NewProgramSyncController creates the controller. interval 0 = 6 h; it
// runs every 15 minutes and syncs the programs due.
func NewProgramSyncController(p ProgramSyncer, interval time.Duration) *ProgramSyncController {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	return &ProgramSyncController{programs: p, interval: interval}
}

// Name implements Controller.
func (c *ProgramSyncController) Name() string { return "program-sync" }

// Interval implements Controller.
func (c *ProgramSyncController) Interval() time.Duration { return 15 * time.Minute }

// Reconcile implements Controller: the number of programs synced.
func (c *ProgramSyncController) Reconcile(ctx context.Context) (int, error) {
	if c.programs == nil {
		return 0, nil
	}
	return c.programs.SyncDue(ctx, c.interval, programSyncBatch)
}
