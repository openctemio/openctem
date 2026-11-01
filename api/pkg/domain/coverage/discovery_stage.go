package coverage

// The discovery stages (docs/architecture/easm.md, "Discovery management"):
// the tenant-level view of the coverage ledger grouped into four stages, with
// a Run per stage, Run all and Abort all. It adds no scheduler: Run makes the
// stage's pairs due now and the coverage loop plans them through the normal
// dispatch gate; Abort all cancels the tenant's active coverage runs through
// the run-cancel path.

import (
	"context"
	"slices"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// DiscoveryStage is one discovery stage.
type DiscoveryStage string

// The stages, in stage order.
const (
	// StageAssetDiscovery finds new names and hosts under the
	// organization's roots (passive sources and active enumeration).
	StageAssetDiscovery DiscoveryStage = "asset_discovery"
	// StageExposureScan looks for what the known surface exposes: open
	// ports and template checks.
	StageExposureScan DiscoveryStage = "exposure_scan"
	// StageValidation gathers the facts attribution and scope decisions
	// read: resolution, registration and network ownership.
	StageValidation DiscoveryStage = "validation_scoping"
	// StageTechnology fingerprints the web services: HTTP probe and
	// crawl, which report the technologies each service runs.
	StageTechnology DiscoveryStage = "technology_discovery"
)

// DiscoveryStages returns the stages in stage order.
func DiscoveryStages() []DiscoveryStage {
	return []DiscoveryStage{StageAssetDiscovery, StageExposureScan, StageValidation, StageTechnology}
}

// Valid reports whether p is a known stage.
func (p DiscoveryStage) Valid() bool { return slices.Contains(DiscoveryStages(), p) }

// discoveryStageOf maps each stage catalog capability the coverage loop can plan to
// its discovery stage. It is the one mapping table: the catalog's phases do
// not separate the four stages (resolve.dns and scan.ports are both
// discovery-phase acts), so the stage is chosen here per capability and a
// test checks it against the catalog and the coverage policy (every planned
// capability maps to exactly one stage, and each entry's catalog phase fits
// its stage). Platform checks (dns.*) run on the attack-surface sweep's
// schedule, not the planner's, so they are in no discovery stage.
var discoveryStageOf = map[string]DiscoveryStage{
	"discover.subdomains":  StageAssetDiscovery,
	"enumerate.subdomains": StageAssetDiscovery,
	"discover.hosts":       StageAssetDiscovery,
	"scan.ports":           StageExposureScan,
	"vuln.templates":       StageExposureScan,
	"check.takeover":       StageExposureScan,
	"resolve.dns":          StageValidation,
	"lookup.rdap":          StageValidation,
	"lookup.asn":           StageValidation,
	"probe.http":           StageTechnology,
	"crawl.web":            StageTechnology,
}

// DiscoveryStageOf returns the discovery stage of a capability (false when it
// is in no discovery stage).
func DiscoveryStageOf(capability string) (DiscoveryStage, bool) {
	p, ok := discoveryStageOf[capability]
	return p, ok
}

// DiscoveryCapabilities returns the capabilities of the given stages that
// the policy plans (planned keeps the policy's order).
func DiscoveryCapabilities(planned []string, stages ...DiscoveryStage) []string {
	out := make([]string, 0, len(planned))
	for _, c := range planned {
		if p, ok := discoveryStageOf[c]; ok && slices.Contains(stages, p) {
			out = append(out, c)
		}
	}
	return out
}

// DiscoveryStatus is a stage's state as shown.
type DiscoveryStatus string

// Statuses.
const (
	// DiscoveryIdle: nothing runs and nothing holds the stage back.
	DiscoveryIdle DiscoveryStatus = "idle"
	// DiscoveryRunning: a coverage run of the stage is active.
	DiscoveryRunning DiscoveryStatus = "running"
	// DiscoveryPaused: the stage cannot run now; Reason says why (the
	// readiness reason, or coverage_off when the organization's automatic
	// coverage is off).
	DiscoveryPaused DiscoveryStatus = "paused"
	// DiscoveryFailed: the latest run of one of its capabilities failed.
	DiscoveryFailed DiscoveryStatus = "failed"
)

// ReasonCoverageOff is the paused reason of every stage while the
// organization's automatic coverage is off.
const ReasonCoverageOff = "coverage_off"

// CapabilityRun is the latest coverage run of one capability.
type CapabilityRun struct {
	RunID       string
	Status      string
	CreatedAt   time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
	// TasksTotal and TasksDone count the run's tasks (filled for an active
	// run only).
	TasksTotal int
	TasksDone  int
}

// Active reports whether the run has not finished.
func (r *CapabilityRun) Active() bool {
	return r != nil && (r.Status == "pending" || r.Status == "running")
}

// failedRunStatuses are the run statuses shown as a failed stage.
var failedRunStatuses = []string{"failed", "timeout", "blocked"}

// CapabilityDiscovery is one capability's ledger figures and latest run.
type CapabilityDiscovery struct {
	Capability string
	Stage      DiscoveryStage
	// Pairs counts the applicable pairs (every state but not_applicable).
	Pairs   int
	Covered int
	// DueNow counts plannable pairs whose time has come.
	DueNow  int
	Queued  int
	Failed  int
	Blocked int
	// Paused counts pairs paused for a readiness reason; PausedReason is
	// that reason.
	Paused        int
	PausedReason  string
	LastAttemptAt *time.Time
	LastSuccessAt *time.Time
	LastRun       *CapabilityRun
}

// StageSummary is one discovery stage as shown.
type StageSummary struct {
	Stage        DiscoveryStage
	Status       DiscoveryStatus
	Reason       string
	LastRunAt    *time.Time
	Capabilities []CapabilityDiscovery
	// Progress: tasks done of the active runs when one is active (unit
	// "tasks"), else covered of the applicable pairs (unit "pairs").
	ProgressDone  int
	ProgressTotal int
	ProgressUnit  string
}

// Progress units.
const (
	ProgressTasks = "tasks"
	ProgressPairs = "pairs"
)

// SummarizeStage folds the capabilities of one stage into its summary. off
// is the organization's automatic coverage being off. Running wins (an
// active run is shown even when coverage was just turned off), then off,
// then a readiness pause, then a failed latest run.
func SummarizeStage(stage DiscoveryStage, caps []CapabilityDiscovery, off bool) StageSummary {
	s := StageSummary{Stage: stage, Status: DiscoveryIdle, Capabilities: caps, ProgressUnit: ProgressPairs}
	running, failed := false, false
	pausedReason := ""
	var tasksDone, tasksTotal, covered, pairs int
	for _, c := range caps {
		pairs += c.Pairs
		covered += c.Covered
		if c.PausedReason != "" && c.Paused > 0 && pausedReason == "" {
			pausedReason = c.PausedReason
		}
		if c.LastRun != nil {
			at := c.LastRun.CreatedAt
			if c.LastRun.StartedAt != nil {
				at = *c.LastRun.StartedAt
			}
			if s.LastRunAt == nil || at.After(*s.LastRunAt) {
				t := at
				s.LastRunAt = &t
			}
			if c.LastRun.Active() {
				running = true
				tasksDone += c.LastRun.TasksDone
				tasksTotal += c.LastRun.TasksTotal
			} else if slices.Contains(failedRunStatuses, c.LastRun.Status) {
				failed = true
			}
		}
	}
	switch {
	case running:
		s.Status = DiscoveryRunning
		s.ProgressDone, s.ProgressTotal, s.ProgressUnit = tasksDone, tasksTotal, ProgressTasks
		return s
	case off:
		s.Status, s.Reason = DiscoveryPaused, ReasonCoverageOff
	case pausedReason != "":
		s.Status, s.Reason = DiscoveryPaused, pausedReason
	case failed:
		s.Status = DiscoveryFailed
	}
	s.ProgressDone, s.ProgressTotal = covered, pairs
	return s
}

// RunNowWait is how far back Run moves a pair's due time: the batch rule's
// wait for the capability (BatchWait), so the next pass starts the batch at
// once instead of holding it for a fuller one.
func RunNowWait(every time.Duration) time.Duration { return BatchWait(every) }

// AutoValidation is the last automatic attribution pass: the assets whose
// automatic attribution decision (no person decided it) was written while the
// latest Validation & scoping run was active, up to AutoValidationSettle after
// it ended (its results are ingested and scored after the run finishes).
// There is no record of an attribution "pass", so this window is the
// definition: the latest run of any Validation & scoping capability.
type AutoValidation struct {
	Assets      int
	WindowStart *time.Time
	WindowEnd   *time.Time
}

// AutoValidationSettle is how long after its run ends an automatic
// attribution write still counts toward that run's pass.
const AutoValidationSettle = 15 * time.Minute

// DiscoveryStore reads and nudges the ledger for the discovery stages. Every
// method is scoped to the tenant.
type DiscoveryStore interface {
	// DiscoveryStats returns the ledger figures and latest coverage run of
	// each capability (capabilities with no pair and no run are absent).
	DiscoveryStats(ctx context.Context, tenantID shared.ID, capabilities []string) ([]CapabilityDiscovery, error)
	// MakeDueNow moves the due time of the capabilities' covered, due and
	// failed pairs back to now minus the capability's wait, so the next
	// coverage pass plans them. Queued, blocked, paused and not applicable
	// pairs are left alone. It returns how many pairs it moved.
	MakeDueNow(ctx context.Context, tenantID shared.ID, waits map[string]time.Duration) (int, error)
	// ActiveCoverageRuns returns the tenant's coverage runs that have not
	// finished.
	ActiveCoverageRuns(ctx context.Context, tenantID shared.ID) ([]shared.ID, error)
	// LastAutoValidation counts the last automatic attribution pass (see
	// AutoValidation) over the given Validation & scoping capabilities.
	LastAutoValidation(ctx context.Context, tenantID shared.ID, capabilities []string) (AutoValidation, error)
}
