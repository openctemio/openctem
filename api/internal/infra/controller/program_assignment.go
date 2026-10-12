package controller

import (
	"context"
	"time"
)

// ProgramAssignments reconciles every program's group assignments with what
// its entries cover (*postgres.BountyProgramRepository).
type ProgramAssignments interface {
	AssignAllPrograms(ctx context.Context) (int64, error)
}

// ProgramAssignmentController keeps the program data scope current (RFC-065
// §7): assets a program's entries cover are assigned to the program's
// group, also those that arrived by discovery or import rather than by the
// program's own scans. Program changes and scan results assign at once;
// this is the safety net. Idempotent.
type ProgramAssignmentController struct {
	programs ProgramAssignments
	interval time.Duration
}

// NewProgramAssignmentController creates the controller. interval 0 = 30 min.
func NewProgramAssignmentController(p ProgramAssignments, interval time.Duration) *ProgramAssignmentController {
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	return &ProgramAssignmentController{programs: p, interval: interval}
}

// Name implements Controller.
func (c *ProgramAssignmentController) Name() string { return "program-assignment" }

// Interval implements Controller.
func (c *ProgramAssignmentController) Interval() time.Duration { return c.interval }

// Reconcile implements Controller: the number of assignments changed.
func (c *ProgramAssignmentController) Reconcile(ctx context.Context) (int, error) {
	if c.programs == nil {
		return 0, nil
	}
	n, err := c.programs.AssignAllPrograms(ctx)
	return int(min(n, int64(1<<30))), err
}
