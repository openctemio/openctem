package validation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SensorCapabilityRetestTemplates prefixes the capability a sensor reports
// when its retest handler for a tool also runs templates delivered with the
// command: "retest-templates:<tool>" (a finding's custom retest check,
// docs/architecture/finding-retest-checks.md). A retest command that carries
// a template requires it next to "retest:<tool>", so an older sensor never
// receives one.
const SensorCapabilityRetestTemplates = "retest-templates"

// RetestTemplatesCapability is the capability a retest command carrying a
// template for tool requires.
func RetestTemplatesCapability(tool string) string {
	return SensorCapabilityRetestTemplates + ":" + strings.ToLower(strings.TrimSpace(tool))
}

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

// RetestToolsOf returns the tools whose findings a sensor with these
// capabilities can re-check: every "retest:<tool>" (the tool's own retest
// handler), plus the tool whose rules the template re-verify rung re-runs
// when the sensor offers that rung. Sorted, without duplicates; malformed
// names are dropped.
func RetestToolsOf(capabilities []string) []string {
	seen := map[string]bool{}
	for _, c := range capabilities {
		c = strings.ToLower(strings.TrimSpace(c))
		if t, ok := strings.CutPrefix(c, SensorCapabilityRetest+":"); ok && ValidRetestTool(t) {
			seen[t] = true
		}
		if c == SensorCapabilityValidateNuclei {
			seen[ReverifyTool] = true
		}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

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
	// Template is the id of the custom template (one of the command's
	// custom_templates) the item is checked with, instead of the sensor's
	// managed template set.
	Template string `json:"template,omitempty"`
}

// RetestTemplatePayload is one custom template of a retest command, in the
// shape of a scan command's custom templates: the platform signs it on
// delivery and the job statement lists its digest.
type RetestTemplatePayload struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	TemplateType string `json:"template_type"`
	// Content is the template, base64 (standard encoding).
	Content string `json:"content"`
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
	// CustomTemplates are the templates the items name (a custom retest
	// check).
	CustomTemplates []RetestTemplatePayload `json:"custom_templates,omitempty"`
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
	// Template is the finding's custom retest check, sent with the command
	// (nil: the tool checks with its own rules).
	Template *RetestTemplate
	// ScanRunID / ScanRunStepID tag the command with the retest's run.
	ScanRunID     shared.ID
	ScanRunStepID shared.ID
	// SensorID addresses the command to one sensor of the tenant (one known
	// to have the rule's template); nil lets any capable sensor claim it.
	// The caller picks it among the tenant's own online sensors.
	SensorID *shared.ID
}

// RetestTemplate is a nuclei template a retest sends with its command.
type RetestTemplate struct {
	ID      string
	Name    string
	Content []byte
}

// retestTemplateFile is the file name a template is sent under.
func retestTemplateFile(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "retest-check"
	}
	if len(out) > 100 {
		out = out[:100]
	}
	return out + ".yaml"
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
	if t := job.Template; t != nil {
		if t.ID == "" || len(t.Content) == 0 {
			return shared.ID{}, fmt.Errorf("%w: a retest template needs an id and content", shared.ErrValidation)
		}
		payload.CustomTemplates = []RetestTemplatePayload{{ID: t.ID, Name: retestTemplateFile(t.Name),
			TemplateType: "nuclei", Content: base64.StdEncoding.EncodeToString(t.Content)}}
		payload.Items[0].Template = t.ID
		payload.RequiredCapabilities = append(payload.RequiredCapabilities, RetestTemplatesCapability(job.Tool))
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
	if job.SensorID != nil {
		cmd.SetSensorID(*job.SensorID)
	}
	if err := d.commands.Create(ctx, cmd); err != nil {
		return shared.ID{}, fmt.Errorf("enqueue retest command: %w", err)
	}
	d.logger.Info("tool retest dispatched",
		"command_id", cmd.ID.String(), "tenant_id", job.TenantID.String(),
		"finding_id", job.FindingID.String(), "tool", job.Tool)
	return cmd.ID, nil
}
