package scanrun

// Chaining scan stages through the inventory (research/27 §5,
// docs/architecture/scan-stages.md): what a stage produced, how the next
// stage was planned from it, and why each target was handed on or not.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Target origins.
const (
	// TargetOriginSeed: a target the run was started with.
	TargetOriginSeed = "seed"
	// TargetOriginDerived: an asset an earlier stage of the run produced.
	TargetOriginDerived = "derived"
)

// Target decisions.
const (
	TargetPlanned = "planned"
	TargetSkipped = "skipped"
)

// Reasons a target was planned or skipped. Planned reasons name the rule
// that allowed it; skipped reasons name what refused it.
const (
	// ReasonSeed: a run target (already gated when the run started).
	ReasonSeed = "seed"
	// ReasonGateAllowed: an active (T1) stage target the ownership gate,
	// scope exclusions, act scope and zone routing all allowed.
	ReasonGateAllowed = "gate_allowed"
	// ReasonPassiveAllowed: a passive (T0) stage target that is not rejected
	// or excluded (a name not confirmed yet may still be resolved).
	ReasonPassiveAllowed = "passive_allowed"

	ReasonExcluded     = "excluded"      // an active scope exclusion
	ReasonUnconfirmed  = "unconfirmed"   // the ownership gate refused it (needs_review, rejected, unattributed, ...)
	ReasonRefused      = "refused"       // the target validator or act scope refused it
	ReasonOtherZone    = "other_zone"    // it routes to another scan zone than the run
	ReasonHopLimit     = "hop_limit"     // more discovery hops from the seeds than allowed
	ReasonOverCap      = "over_cap"      // a fan-out cap bit
	ReasonDuplicate    = "duplicate"     // already a target of the stage (a seed or another parent's child)
	ReasonInvalid      = "invalid"       // not a well-formed host, address or URL
	ReasonNotChainable = "not_chainable" // an intrusive (T2) stage is never fed derived targets
	ReasonUnchanged    = "unchanged"     // an origin with no new or changed endpoint (endpoint_selector)
)

// StepOutput is one asset a stage of a run produced, as the inventory has
// it now.
// StepOutputCount is how many live assets of one type a step run of a run
// produced (the run map's per-step outputs).
type StepOutputCount struct {
	StepRunID shared.ID
	AssetType string
	Count     int
}

type StepOutput struct {
	StepRunID shared.ID
	AssetID   shared.ID
	Name      string
	Type      string
	SubType   string
	// New: the previous run of the scan did not produce it in the same step
	// (set by PreviewStepOutputs when it compares).
	New bool
}

// StepOutputDelta compares what one step (by key) produced in a run with
// the previous run of the same scan: how many assets the previous run
// produced, how many this run produced that the previous did not (added),
// and how many the previous run produced that this one did not (gone).
type StepOutputDelta struct {
	StepKey  string
	Previous int
	Added    int
	Gone     int
}

// StagePlan is how one stage of a run was planned: the exactly-once record
// of planning and the counts the run view shows.
type StagePlan struct {
	TenantID  shared.ID
	RunID     shared.ID
	StageKey  string // the step key
	Stage     string // catalog capability ("" for a step the catalog cannot place)
	Tool      string
	Tier      int
	Chained   bool // it took targets from an earlier stage's outputs
	Inputs    int  // seeds plus candidate outputs considered
	Planned   int
	MaxHop    int
	Skipped   map[string]int // reason -> count
	PlannedAt time.Time
}

// RunTarget is one target a stage was handed or refused, with its
// provenance.
type RunTarget struct {
	TenantID       shared.ID
	RunID          shared.ID
	StageKey       string
	TargetKey      string
	AssetID        *shared.ID
	Origin         string
	ParentAssetID  *shared.ID
	ParentStageKey string
	Relation       string
	Hop            int
	Decision       string
	Reason         string
}

// HopRepository stores what stages produced and how the next stages were
// planned. Every method is scoped to the tenant it is given; ids of another
// tenant read and write nothing.
type HopRepository interface {
	// RecordStepOutputs records assets a command-bound report wrote for a
	// step run of the tenant. Assets and step runs of other tenants are
	// ignored. Returns how many rows were new.
	RecordStepOutputs(ctx context.Context, tenantID, stepRunID shared.ID, assetIDs []shared.ID) (int, error)
	// ListStepOutputs returns up to limit live assets the given step runs of
	// the run produced, and how many there are in all.
	ListStepOutputs(ctx context.Context, tenantID, runID shared.ID, stepRunIDs []shared.ID, limit int) ([]StepOutput, int, error)
	// CountStepOutputs counts, per step run and asset type, the live assets
	// the run's step runs produced. A non-nil scope counts only the assets
	// the caller may see.
	CountStepOutputs(ctx context.Context, tenantID, runID shared.ID, scope *shared.DataScope) ([]StepOutputCount, error)
	// PreviousRun returns the latest finished (completed or partial) run of
	// the same scan created before the run, or a zero id when there is none
	// (or the run has no scan).
	PreviousRun(ctx context.Context, tenantID, runID shared.ID) (shared.ID, error)
	// CompareStepOutputs compares, per step key, the live assets the run and
	// the previous run produced. A non-nil scope counts only the assets the
	// caller may see.
	CompareStepOutputs(ctx context.Context, tenantID, runID, previousRunID shared.ID, scope *shared.DataScope) ([]StepOutputDelta, error)
	// PreviewStepOutputs returns up to limit live assets one step (by key) of
	// the run produced, new ones first, and how many there are in all; New
	// is set against the previous run (zero: none, nothing is new). A
	// non-nil scope lists and counts only the assets the caller may see.
	PreviewStepOutputs(ctx context.Context, tenantID, runID, previousRunID shared.ID, stepKey string, scope *shared.DataScope, limit int) ([]StepOutput, int, error)
	// PendingStepIngest reports whether a sensor report of any command of
	// the given step runs is still being received or ingested.
	PendingStepIngest(ctx context.Context, tenantID shared.ID, stepRunIDs []shared.ID) (bool, error)
	// SaveStagePlan stores a stage's plan and its targets in one
	// transaction, unless the stage of that run was planned already
	// (planned == false: nothing written).
	SaveStagePlan(ctx context.Context, plan *StagePlan, targets []RunTarget) (planned bool, err error)
	// PlannedTargets returns the planned targets of the given stages of a
	// run (the parents a derived target is traced to).
	PlannedTargets(ctx context.Context, tenantID, runID shared.ID, stageKeys []string) ([]RunTarget, error)
	// ListStagePlans returns the stage plans of a run.
	ListStagePlans(ctx context.Context, tenantID, runID shared.ID) ([]StagePlan, error)
	// StepRunOfCommand returns the run and step key of a command's step run
	// in the tenant (shared.ErrNotFound when it has none).
	StepRunOfCommand(ctx context.Context, tenantID, commandID shared.ID) (runID shared.ID, stepKey string, err error)
}
