package scanrun

// Tasks of a run (RFC-046 §4.1, docs/rfcs/RFC-046-scans-redesign.md): until
// RFC-030 chunks land, a task is one command the run dispatched: one tool, a
// slice of targets, one sensor attempt at a time.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TaskStatus is a task's state as the runs page shows it. Command states map
// onto it: pending → queued, acknowledged/running → running, failed/expired →
// failed.
type TaskStatus string

const (
	TaskStatusQueued    TaskStatus = "queued"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusCanceled  TaskStatus = "canceled"
)

// TaskSummary counts a run's tasks by status.
type TaskSummary struct {
	Total     int
	Queued    int
	Running   int
	Completed int
	Failed    int
	Canceled  int
	// Sensors is how many distinct sensors claimed one of the tasks.
	Sensors int
}

// Task is one unit of a run's work.
type Task struct {
	ID        shared.ID
	StepRunID *shared.ID
	StepKey   string
	Tool      string
	Status    TaskStatus
	// SensorID and SensorName name the tenant sensor that claimed or was
	// pinned the task. A shared platform sensor is reported as Platform with
	// no id or name.
	SensorID     *shared.ID
	SensorName   string
	Platform     bool
	Targets      int
	Attempts     int
	CreatedAt    time.Time
	StartedAt    *time.Time
	CompletedAt  *time.Time
	ErrorMessage string
	// Progress is the finished targets its sensor last reported (nil: none
	// reported, e.g. an older sensor or a queued task). Untrusted, bounded
	// by the task's target count when recorded.
	Progress *TaskProgress
	// BudgetSeconds and StallSeconds are the task's expected time and stall
	// window from its budget (0: the task carries none; research/122).
	BudgetSeconds int
	StallSeconds  int
	// Skipped are the targets the sensor's local policy skipped in a task
	// that completed on the rest (at most MaxTaskSkippedTargets; cleaned);
	// SkippedTotal counts all of them.
	Skipped      []SkippedTarget
	SkippedTotal int
	// CoverageGaps are the hosts the sensor could not fully cover in a
	// task that completed (at most MaxTaskCoverageGaps; cleaned);
	// CoverageGapsTotal counts all of them.
	CoverageGaps      []CoverageGap
	CoverageGapsTotal int
	// WindowHold says why a queued task waits for a scan window and until
	// when (nil: it does not).
	WindowHold *scanwindow.Hold
	// WaitingOnHosts: a queued task waits while another task of the tenant
	// holds one of its hosts.
	WaitingOnHosts bool
}

// MaxRunTasks bounds the tasks one run read returns; the summary still counts
// all of them.
const MaxRunTasks = 200

// TaskReader reads the tasks of runs. Every read is scoped to tenantID: a run
// of another tenant has no tasks.
type TaskReader interface {
	// ListRunTasks returns up to limit tasks of runID in dispatch order and
	// the summary of all of them.
	ListRunTasks(ctx context.Context, tenantID, runID shared.ID, limit int) ([]Task, TaskSummary, error)
	// TaskSummaries returns the task summary of each of runIDs that has
	// tasks.
	TaskSummaries(ctx context.Context, tenantID shared.ID, runIDs []shared.ID) (map[shared.ID]TaskSummary, error)
}

// TaskProgress is a running task's finished targets and when the count last
// grew (the stall clock).
type TaskProgress struct {
	Done   int
	Total  int
	LastAt *time.Time
}
