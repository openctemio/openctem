package ingest

// Source-asserted resolve (docs/rfcs/RFC-047-tenable-sc-sensor-connector.md
// §7.6): a source that keeps its own "mitigated" database (Tenable.sc) says
// explicitly that a vulnerability is gone. Such a finding is never stored as a
// sighting; it resolves the matching open finding when all of these hold:
//
//   - the report is bound to a command assigned to the submitting sensor;
//   - the report's tool is a source the platform trusts to say so
//     (sourceResolveTools) and the finding was last seen by that same tool,
//     so a Tenable mitigation never closes another tool's sighting;
//   - the finding is open (new, open, confirmed, in progress, fix applied),
//     never false positive, accepted or already resolved, and not from a
//     human source (pentest, manual, bug bounty, red team);
//   - the source's mitigation time is not older than the finding's last
//     sighting.
//
// Mode (INGEST_SOURCE_RESOLVE): off, dry_run (the default: count and log,
// no state change) or enforce. A mitigated row that matches no finding
// creates nothing.

import (
	"context"
	"strings"
	"time"

	"github.com/openctemio/ctis"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// SourceResolveMode is how source-asserted resolve acts.
type SourceResolveMode string

const (
	SourceResolveOff     SourceResolveMode = "off"
	SourceResolveDryRun  SourceResolveMode = "dry_run"
	SourceResolveEnforce SourceResolveMode = "enforce"
)

// ParseSourceResolveMode reads the configured mode. Anything that is not
// "off" or "enforce" is dry_run: an unknown value must never start closing
// findings.
func ParseSourceResolveMode(v string) SourceResolveMode {
	switch SourceResolveMode(strings.ToLower(strings.TrimSpace(v))) {
	case SourceResolveOff:
		return SourceResolveOff
	case SourceResolveEnforce:
		return SourceResolveEnforce
	default:
		return SourceResolveDryRun
	}
}

// sourceResolveTools are the tools whose "mitigated" state the platform acts
// on. A tool not listed here never resolves anything by its say-so, and its
// resolved-status findings are ingested like any other.
var sourceResolveTools = map[string]bool{
	"tenable_sc": true,
}

// sourceMitigatedState is the property value a connector sets on a finding
// that its source moved to the mitigated database.
const sourceMitigatedState = "mitigated"

// sourceResolver is implemented by the postgres finding repository. Optional:
// a repository without it (tests, mocks) disables the feature.
type sourceResolver interface {
	ResolveSourceMitigated(ctx context.Context, tenantID shared.ID, tool string,
		items []vulnerability.SourceMitigation, dryRun bool) ([]shared.ID, error)
}

// SetSourceResolveMode sets the source-asserted resolve mode.
func (s *Service) SetSourceResolveMode(mode SourceResolveMode) {
	s.findingProcessor.sourceResolveMode = mode
}

func (p *FindingProcessor) sourceResolve() SourceResolveMode {
	if p.sourceResolveMode == "" {
		return SourceResolveDryRun
	}
	return p.sourceResolveMode
}

// isSourceMitigated reports whether a report finding is its source's
// statement that the vulnerability is mitigated: a tool in
// sourceResolveTools, status resolved, and tenable_state "mitigated".
func isSourceMitigated(report *ctis.Report, f *ctis.Finding) bool {
	if report == nil || report.Tool == nil || f == nil {
		return false
	}
	if !sourceResolveTools[strings.ToLower(strings.TrimSpace(report.Tool.Name))] {
		return false
	}
	if f.Status != ctis.FindingStatusResolved {
		return false
	}
	state, _ := f.Properties["tenable_state"].(string)
	return strings.EqualFold(strings.TrimSpace(state), sourceMitigatedState)
}

// mitigatedAt is when the source says the finding was mitigated: the
// tenable_last_mitigated property (RFC 3339), else its last sighting, else
// now. Never in the future.
func mitigatedAt(f *ctis.Finding, now time.Time) time.Time {
	t := now
	if v, ok := f.Properties["tenable_last_mitigated"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(v)); err == nil {
			t = parsed
		}
	} else if f.LastSeenAt != nil {
		t = *f.LastSeenAt
	}
	if t.After(now) {
		t = now
	}
	return t.UTC()
}

// applySourceMitigations resolves (or counts, in dry_run) the open findings
// the report's source said are mitigated.
func (p *FindingProcessor) applySourceMitigations(ctx context.Context, tenantID shared.ID, report *ctis.Report,
	items []vulnerability.SourceMitigation, scope *alterScope, output *Output) {
	if len(items) == 0 {
		return
	}
	output.FindingsSourceMitigated += len(items)
	mode := p.sourceResolve()
	if mode == SourceResolveOff || scope == nil || !scope.commandBound {
		return
	}
	tool := strings.ToLower(strings.TrimSpace(report.Tool.Name))
	if items = sourceResolvable(scope, tool, items); len(items) == 0 {
		return
	}
	repo, ok := p.repo.(sourceResolver)
	if !ok {
		return
	}
	ids, err := repo.ResolveSourceMitigated(ctx, tenantID, tool, items, mode != SourceResolveEnforce)
	if err != nil {
		p.logger.Warn("source-asserted resolve failed", "tenant_id", tenantID.String(), "tool", logValue(tool), "error", err)
		addError(output, "source-asserted resolve failed")
		return
	}
	output.SourceResolveIDs = append(output.SourceResolveIDs, ids...)
	output.SourceResolveMode = mode
	if mode == SourceResolveEnforce {
		output.FindingsSourceResolved += len(ids)
	} else {
		output.FindingsSourceWouldResolve += len(ids)
	}
	if len(ids) > 0 {
		p.logger.Info("source-asserted resolve", "tenant_id", tenantID.String(), "tool", logValue(tool),
			"mode", string(mode), "findings", len(ids), "mitigated_rows", len(items))
	}
}

// auditSourceResolve records, once per report, the findings source-asserted
// resolve closed (enforce) or would have closed (dry_run).
func (s *Service) auditSourceResolve(ctx context.Context, tenantID shared.ID, binding Binding, tool string, out *Output) {
	if len(out.SourceResolveIDs) == 0 || (s.auditSvc == nil && s.auditRepo == nil) {
		return
	}
	action := audit.ActionIngestSourceResolved
	if out.SourceResolveMode != SourceResolveEnforce {
		action = audit.ActionIngestSourceResolveDryRun
	}
	ids := out.SourceResolveIDs
	listed := make([]string, 0, min(len(ids), maxAuditedFindingIDs))
	for i, id := range ids {
		if i == maxAuditedFindingIDs {
			break
		}
		listed = append(listed, id.String())
	}
	resource := out.ReportID
	if binding.CommandID != nil {
		resource = binding.CommandID.String()
	}
	event := auditapp.NewSuccessEvent(action, audit.ResourceTypeIngest, resource)
	event.ResourceName = logValue(tool)
	event.Message = "source-asserted resolve: the source reported these findings mitigated"
	event.Metadata = map[string]any{
		"mode": string(out.SourceResolveMode), "tool_name": logValue(tool), "count": len(ids),
		"mitigated_rows": out.FindingsSourceMitigated,
		"finding_ids":    listed, "finding_ids_truncated": len(ids) > maxAuditedFindingIDs,
	}
	if err := s.writeIngestAuditLog(ctx, auditapp.AuditContext{TenantID: tenantID.String()}, event); err != nil {
		s.logger.Warn("failed to write source-asserted resolve audit log", "error", err)
	}
}

// sourceResolvable keeps the mitigations a bound report may close on its
// source's say-so. Only a connector command of the same tool may: a sync
// covers the connector's whole inventory, a connector scan only the assets
// this report may change (its targets and what it created). Any other
// command (a scan, a validate command that names no tool) resolves nothing,
// so a report cannot choose a source tool to close another tool's findings.
func sourceResolvable(scope *alterScope, tool string, items []vulnerability.SourceMitigation) []vulnerability.SourceMitigation {
	if scope.commandTool == "" || !tooldom.SameTool(scope.commandTool, tool) {
		return nil
	}
	switch scope.commandType {
	case command.CommandTypeConnectorSync:
		return items
	case command.CommandTypeConnectorScan:
		kept := items[:0:0]
		for _, it := range items {
			if scope.allowedAsset(it.AssetID) {
				kept = append(kept, it)
			}
		}
		return kept
	default:
		return nil
	}
}
