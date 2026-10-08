package validation

import (
	"context"
	"encoding/json"
	"fmt"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SensorCapabilityValidate is the capability string a validate-capable sensor
// advertises and the one a validate command requires for routing. It is the
// single source of truth shared by the dispatch payload (RequiredCapabilities)
// and the pre-flight availability gate (RunService.ensureSensorAvailable) so the
// two never drift: the gate opens exactly when a queued command can be routed.
const SensorCapabilityValidate = "validate"

// SensorCapabilityValidateNuclei is the capability a nuclei-re-verify-capable
// sensor advertises (RFC-011.2 Phase 2b). It is strictly deeper than
// SensorCapabilityValidate: a sensor that can run a single detection template
// advertises BOTH, and a KindNuclei command requires this one so it is only ever
// routed to a sensor that can execute it — never a safe-check-only sensor. The
// gate that decides whether to route KindNuclei (NucleiAvailability) queries for
// exactly this capability, so the two never drift.
const SensorCapabilityValidateNuclei = "validate:nuclei"

// CommandCreator is the narrow seam over the command repository used to enqueue
// a validation job. Implemented by *postgres.CommandRepository.
type CommandCreator interface {
	Create(ctx context.Context, cmd *commanddom.Command) error
}

// JobDispatcher enqueues a validation job for a sensor to execute and returns
// the command ID it was queued under. It is fire-and-forget: the sensor reports
// the result later and the command-completion hook maps that result back into
// Evidence via EvidenceIngestService. (This is the async counterpart to the
// synchronous ValidationDispatcher.Submit contract, which does not fit the
// platform's poll/complete queue.)
type JobDispatcher interface {
	Dispatch(ctx context.Context, job ValidationJob) (shared.ID, error)
}

// ValidateTargetPayload is the target section of a validate command payload.
type ValidateTargetPayload struct {
	AssetID string `json:"asset_id"`
	Type    string `json:"type"`
	Address string `json:"address"`
}

// ValidateCommandPayload is the JSON payload embedded in a CommandTypeValidate
// command. It is the wire contract between the API (producer) and the sensor
// executor (consumer); the sensor replies with a ValidateResultPayload.
type ValidateCommandPayload struct {
	JobID     string `json:"job_id"`
	FindingID string `json:"finding_id"`
	// SimulationRunID is set when the job backs an attack-simulation run
	// (RFC-012). The sensor ignores it; the server completion hook uses it to
	// finalize the run. Empty for plain finding proof-of-fix jobs.
	SimulationRunID string                `json:"simulation_run_id,omitempty"`
	ExecutorKind    string                `json:"executor_kind"`
	Technique       string                `json:"technique"`
	Target          ValidateTargetPayload `json:"target"`
	TimeoutSeconds  int                   `json:"timeout_seconds"`
	// TemplateID / CVEID carry the finding's own detection signature for a
	// KindNuclei job (RFC-011.2 Phase 2b): the sensor re-runs this single template
	// (`nuclei -id <template_id|cve_id>`), never a full scan. Both empty for a
	// safe-check job, which the sensor then handles as today.
	TemplateID string `json:"template_id,omitempty"`
	CVEID      string `json:"cve_id,omitempty"`
	// RetestID is set when the job is one of a finding retest's two checks
	// (RFC-039). The sensor ignores it; the completion hook records the
	// evidence advisory-only and hands the result to the retest service.
	RetestID string `json:"retest_id,omitempty"`
	// RequiredCapabilities lets the platform route the job only to sensors that
	// advertise the validation capability (mirrors the scan command payload).
	RequiredCapabilities []string `json:"required_capabilities"`
	// ScanRunID is the run that holds the command (its tasks and logs).
	// The sensor ignores it; it is not a step key, so the scan run service
	// does not drive the run from the command result.
	ScanRunID string `json:"scan_run_id,omitempty"`
}

// ValidateResultPayload is what a sensor reports back in the command result for
// a validate command. Kept small and stable; RawMeta carries probe detail.
type ValidateResultPayload struct {
	Outcome  string         `json:"outcome"`
	Summary  string         `json:"summary"`
	Evidence map[string]any `json:"evidence,omitempty"`
}

// CommandDispatcher implements JobDispatcher by creating a CommandTypeValidate
// command that a validate-capable sensor polls and executes. It is the only
// producer of validate commands, and every job passes the active-probe gate
// here before a command exists: a refused target, an unwired gate or a gate
// error dispatches nothing.
type CommandDispatcher struct {
	commands CommandCreator
	gate     TargetGate
	logger   *logger.Logger
}

// NewCommandDispatcher wires the dispatcher over the command repository and
// the active-probe gate. A nil gate refuses every job (fail closed).
func NewCommandDispatcher(commands CommandCreator, gate TargetGate, log *logger.Logger) *CommandDispatcher {
	return &CommandDispatcher{
		commands: commands,
		gate:     gate,
		logger:   log.With("service", "validation-dispatcher"),
	}
}

// Preflight runs a target through the active-probe gate without dispatching
// anything, so a caller can refuse a request before it records state.
// Dispatch runs the same check again; Preflight never replaces it.
func (d *CommandDispatcher) Preflight(ctx context.Context, tenantID shared.ID, t Target) error {
	_, err := CheckTarget(ctx, d.gate, tenantID, t)
	return err
}

// Dispatch enqueues the job as a tenant command and returns the command ID.
func (d *CommandDispatcher) Dispatch(ctx context.Context, job ValidationJob) (shared.ID, error) {
	// A job must carry a tenant and at least one subject to reconcile against —
	// a finding (proof-of-fix) and/or a simulation run (RFC-012 BAS).
	if job.TenantID.IsZero() || (job.FindingID.IsZero() && job.SimulationRunID.IsZero()) {
		return shared.ID{}, fmt.Errorf("%w: tenant and a finding or simulation run are required", shared.ErrValidation)
	}

	findingID := ""
	if !job.FindingID.IsZero() {
		findingID = job.FindingID.String()
	}
	simRunID := ""
	if !job.SimulationRunID.IsZero() {
		simRunID = job.SimulationRunID.String()
	}
	retestID := ""
	if !job.RetestID.IsZero() {
		retestID = job.RetestID.String()
	}

	// Route a KindNuclei job only to sensors advertising the deeper
	// `validate:nuclei` capability; everything else rides the base `validate`
	// capability. The kind is already capability-gated upstream (RunService only
	// selects KindNuclei when a nuclei sensor is online), so this required
	// capability can never enqueue a command no sensor can consume.
	requiredCap := SensorCapabilityValidate
	if job.ExecutorKind == KindNuclei {
		requiredCap = SensorCapabilityValidateNuclei
	}

	payload := ValidateCommandPayload{
		JobID:           job.JobID.String(),
		FindingID:       findingID,
		SimulationRunID: simRunID,
		ExecutorKind:    string(job.ExecutorKind),
		Technique:       string(job.Technique),
		Target: ValidateTargetPayload{
			AssetID: job.Target.AssetID.String(),
			Type:    job.Target.Type,
			Address: job.Target.Address,
		},
		TimeoutSeconds:       job.TimeoutSeconds,
		TemplateID:           job.TemplateID,
		CVEID:                job.CVEID,
		RetestID:             retestID,
		RequiredCapabilities: []string{requiredCap},
		ScanRunID:            idString(job.ScanRunID),
	}

	// The active-probe gate: exclusions, the private-range policy, the
	// asset's attribution and scan-zone routing, as for a scan.
	zone, err := CheckTarget(ctx, d.gate, job.TenantID, job.Target)
	if err != nil {
		d.logger.Info("validation job refused by the active-probe gate",
			"tenant_id", job.TenantID.String(),
			"asset_id", job.Target.AssetID.String(),
			"executor_kind", string(job.ExecutorKind),
			"reason", err.Error(),
		)
		return shared.ID{}, err
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return shared.ID{}, fmt.Errorf("marshal validate payload: %w", err)
	}

	cmd, err := commanddom.NewCommand(job.TenantID, commanddom.CommandTypeValidate, commanddom.CommandPriorityNormal, raw)
	if err != nil {
		return shared.ID{}, fmt.Errorf("build validate command: %w", err)
	}
	if zone != nil {
		// Only the zone's sensors may claim the probe (zoneClaimPredicate).
		cmd.SetScanZone(zone.ID)
	}
	if !job.ScanRunStepID.IsZero() {
		cmd.SetStepRunID(job.ScanRunStepID)
	}

	if err := d.commands.Create(ctx, cmd); err != nil {
		return shared.ID{}, fmt.Errorf("enqueue validate command: %w", err)
	}

	d.logger.Info("validation job dispatched",
		"command_id", cmd.ID.String(),
		"tenant_id", job.TenantID.String(),
		"finding_id", job.FindingID.String(),
		"executor_kind", string(job.ExecutorKind),
		"technique", string(job.Technique),
	)
	return cmd.ID, nil
}

// idString is the id's string form, or "" for a zero id (omitted in JSON).
func idString(id shared.ID) string {
	if id.IsZero() {
		return ""
	}
	return id.String()
}
