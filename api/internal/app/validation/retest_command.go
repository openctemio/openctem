package validation

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SensorCapabilityRetest prefixes the capability a sensor reports for a tool
// with a retest handler: "retest:<tool>" (RFC-039, tool retest). A retest
// command requires exactly that capability, and the availability check asks
// for the same string, so the two never drift.
const SensorCapabilityRetest = "retest"

// RetestCapability is the capability a retest command for tool requires.
func RetestCapability(tool string) string {
	return SensorCapabilityRetest + ":" + strings.ToLower(strings.TrimSpace(tool))
}

var retestToolRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidRetestTool reports whether tool is a well-formed tool name for a retest
// command (lowercase; the name a sensor's manifest registers).
func ValidRetestTool(tool string) bool { return retestToolRe.MatchString(tool) }

// RetestItemPayload is one known finding the tool re-checks.
type RetestItemPayload struct {
	// Ref is the finding id; the verdict for it must carry the same ref.
	Ref string `json:"ref"`
	// Target is the address the finding is on: one entry of the command's
	// targets.
	Target      string `json:"target"`
	Kind        string `json:"kind"`
	RuleID      string `json:"rule_id"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// RetestCommandPayload is the payload of a CommandTypeRetest command: the wire
// contract with the sensor runtime (sdk-go sensorkit retest command, tool
// contract retest). It names the tool under "scanner" and lists plain target
// addresses, as a scan command does, so the claim-time tool predicate, the
// sensor's admission of every target against its local policy, and per-host
// scheduling read it unchanged.
type RetestCommandPayload struct {
	Scanner        string              `json:"scanner"`
	RetestID       string              `json:"retest_id"`
	TimeoutSeconds int                 `json:"timeout_seconds"`
	Targets        []string            `json:"targets"`
	Items          []RetestItemPayload `json:"items"`
	// RequiredCapabilities routes the command only to sensors whose tool has
	// a retest handler (["retest:<tool>"]).
	RequiredCapabilities []string `json:"required_capabilities"`
	// ScanRunID is the run that holds the command (its tasks and logs).
	// The sensor ignores it; it is not a step key, so the scan run service
	// does not drive the run from the command result.
	ScanRunID string `json:"scan_run_id,omitempty"`
}

// ToolRetestJob is one finding re-checked by its own tool's retest handler.
type ToolRetestJob struct {
	TenantID  shared.ID
	FindingID shared.ID
	RetestID  shared.ID
	// Tool is the finding's tool (lowercase).
	Tool string
	// Target is the finding's own asset address, resolved by the caller;
	// it passes the active-probe gate here.
	Target         Target
	RuleID         string
	Fingerprint    string
	TimeoutSeconds int
	// ScanRunID / ScanRunStepID tag the command with the retest's run.
	ScanRunID     shared.ID
	ScanRunStepID shared.ID
}

// DispatchToolRetest enqueues one retest command. The target passes the same
// active-probe gate as every validate command (exclusions, private ranges,
// attribution, scan zones); a refused target dispatches nothing.
func (d *CommandDispatcher) DispatchToolRetest(ctx context.Context, job ToolRetestJob) (shared.ID, error) {
	if job.TenantID.IsZero() || job.FindingID.IsZero() || job.RetestID.IsZero() {
		return shared.ID{}, fmt.Errorf("%w: tenant, finding and retest are required", shared.ErrValidation)
	}
	if !ValidRetestTool(job.Tool) {
		return shared.ID{}, fmt.Errorf("%w: invalid tool name", shared.ErrValidation)
	}
	if strings.TrimSpace(job.Target.Address) == "" || strings.TrimSpace(job.RuleID) == "" {
		return shared.ID{}, fmt.Errorf("%w: a target and a rule id are required", shared.ErrValidation)
	}

	zone, err := CheckTarget(ctx, d.gate, job.TenantID, job.Target)
	if err != nil {
		d.logger.Info("tool retest refused by the active-probe gate",
			"tenant_id", job.TenantID.String(), "asset_id", job.Target.AssetID.String(),
			"tool", job.Tool, "reason", err.Error())
		return shared.ID{}, err
	}

	payload := RetestCommandPayload{
		Scanner:        job.Tool,
		RetestID:       job.RetestID.String(),
		TimeoutSeconds: job.TimeoutSeconds,
		Targets:        []string{job.Target.Address},
		Items: []RetestItemPayload{{
			Ref: job.FindingID.String(), Target: job.Target.Address, Kind: "finding",
			RuleID: job.RuleID, Fingerprint: job.Fingerprint,
		}},
		RequiredCapabilities: []string{RetestCapability(job.Tool)},
		ScanRunID:            idString(job.ScanRunID),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return shared.ID{}, fmt.Errorf("marshal retest payload: %w", err)
	}
	cmd, err := commanddom.NewCommand(job.TenantID, commanddom.CommandTypeRetest, commanddom.CommandPriorityNormal, raw)
	if err != nil {
		return shared.ID{}, fmt.Errorf("build retest command: %w", err)
	}
	// What CheckTarget checked: the claim re-checks it.
	rec := commanddom.ProbeDispatchGate
	cmd.DispatchGate = &rec
	if zone != nil {
		cmd.SetScanZone(zone.ID)
	}
	if !job.ScanRunStepID.IsZero() {
		cmd.SetStepRunID(job.ScanRunStepID)
	}
	if err := d.commands.Create(ctx, cmd); err != nil {
		return shared.ID{}, fmt.Errorf("enqueue retest command: %w", err)
	}
	d.logger.Info("tool retest dispatched",
		"command_id", cmd.ID.String(), "tenant_id", job.TenantID.String(),
		"finding_id", job.FindingID.String(), "tool", job.Tool)
	return cmd.ID, nil
}
