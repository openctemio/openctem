package ingest

// Report output-type binding (research/27 P0-4, owner decision G12;
// RFC-040 §5.3 "same kind of output"; docs/architecture/scan-stages.md).
//
// A report bound to a command may carry only the asset types the command's
// tool is declared to produce or take (its scan stages in pkg/domain/stage:
// outputs, plus inputs it re-observes). A dnsx report naming a repository,
// or an httpx report minting cloud accounts, is out of its contract: a
// compromised or buggy sensor must not plant arbitrary assets through a
// legitimate command. What is out of contract follows the tenant's result
// policy (the #889 modes): in "quarantine" mode those assets, and the
// findings on them, are held for review and not applied; in "warn" mode
// (existing tenants) they are applied and the tenant's audit log says so.
// A tool the catalog does not know (a tenant's custom tool) has no contract
// and is not checked.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/openctemio/ctis"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// maxContractTypesLogged bounds the type labels named in one log or audit
// entry; the counts are always exact.
const maxContractTypesLogged = 10

// outputContract returns the stages whose contract a report of tool must
// keep, or nil when the catalog does not know the tool.
func outputContract(tool string) []stage.Stage {
	return stage.ForTool(tool)
}

// inContract reports whether one of the stages may report an asset of the
// stored pair.
func inContract(stages []stage.Stage, ref asset.TypeRef) bool {
	for _, st := range stages {
		if st.MayReport(ref) {
			return true
		}
	}
	return false
}

// contractSplit is a report divided by its tool's contract.
type contractSplit struct {
	kept, held    *ctis.Report
	heldTypes     map[string]int // type label -> assets out of contract
	heldFindings  int
	heldAssetRefs map[string]bool
}

// splitByContract divides a report into what its tool's contract allows and
// what it does not: the out-of-contract assets and the findings that name
// them. The input report is not changed.
func splitByContract(report *ctis.Report, stages []stage.Stage) *contractSplit {
	sp := &contractSplit{heldTypes: map[string]int{}, heldAssetRefs: map[string]bool{}}
	keptAssets := make([]ctis.Asset, 0, len(report.Assets))
	heldAssets := make([]ctis.Asset, 0, len(report.Assets)-len(keptAssets))
	for i := range report.Assets {
		a := report.Assets[i]
		rt := resolveCTISAssetType(&a).stored
		ref := asset.TypeRef{Type: rt.Type, SubType: rt.SubType}
		if rt.Type != asset.AssetTypeUnclassified && inContract(stages, ref) {
			keptAssets = append(keptAssets, a)
			continue
		}
		heldAssets = append(heldAssets, a)
		sp.heldTypes[stage.Label(ref)]++
		if a.ID != "" {
			sp.heldAssetRefs[a.ID] = true
		}
	}
	if len(heldAssets) == 0 {
		return sp
	}
	keptFindings := make([]ctis.Finding, 0, len(report.Findings))
	var heldFindings []ctis.Finding
	for _, f := range report.Findings {
		if f.AssetRef != "" && sp.heldAssetRefs[f.AssetRef] {
			heldFindings = append(heldFindings, f)
			continue
		}
		keptFindings = append(keptFindings, f)
	}
	kept := *report
	kept.Assets, kept.Findings = keptAssets, keptFindings
	held := *report
	held.Assets, held.Findings = heldAssets, heldFindings
	held.Dependencies = nil
	sp.kept, sp.held, sp.heldFindings = &kept, &held, len(heldFindings)
	return sp
}

// typeSummary names the held types, most frequent first, bounded.
func (sp *contractSplit) typeSummary() []map[string]any {
	labels := make([]string, 0, len(sp.heldTypes))
	for l := range sp.heldTypes {
		labels = append(labels, l)
	}
	sort.Slice(labels, func(i, j int) bool {
		if sp.heldTypes[labels[i]] != sp.heldTypes[labels[j]] {
			return sp.heldTypes[labels[i]] > sp.heldTypes[labels[j]]
		}
		return labels[i] < labels[j]
	})
	out := make([]map[string]any, 0, min(len(labels), maxContractTypesLogged))
	for _, l := range labels[:min(len(labels), maxContractTypesLogged)] {
		out = append(out, map[string]any{"type": l, "assets": sp.heldTypes[l]})
	}
	return out
}

func (sp *contractSplit) heldCount() int {
	if sp.held == nil {
		return 0
	}
	return len(sp.held.Assets)
}

// bindOutputTypes applies the output-type contract to a command-bound
// sensor report and returns the report to apply. In quarantine mode the
// out-of-contract part is stored for review (never applied, even when the
// quarantine cannot take it); in warn mode the report is applied whole.
func (s *Service) bindOutputTypes(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID, binding Binding,
	report *ctis.Report, opts Options,
) *ctis.Report {
	if binding.Kind != BindingCommand || report == nil || len(report.Assets) == 0 {
		return report
	}
	tool := binding.Tool
	if tool == "" && report.Tool != nil {
		tool = report.Tool.Name
	}
	stages := outputContract(tool)
	if len(stages) == 0 {
		return report // no contract for a tool the catalog does not know
	}
	sp := splitByContract(report, stages)
	if sp.heldCount() == 0 {
		return report
	}
	mode := s.ResultPolicy(ctx, tenantID).Mode
	event := auditapp.NewSuccessEvent(audit.ActionSensorResultsQuarantined, audit.ResourceTypeSensor, agt.ID.String()).
		WithResourceName(agt.Name).
		WithSeverity(audit.SeverityMedium).
		WithMetadata("reason", string(sensorresult.ReasonOutOfContract)).
		WithMetadata("tool_name", tool).
		WithMetadata("report_id", report.Metadata.ID).
		WithMetadata("out_of_contract_assets", sp.heldCount()).
		WithMetadata("out_of_contract_findings", sp.heldFindings).
		WithMetadata("types", sp.typeSummary()).
		WithMetadata("mode", string(mode))
	if binding.CommandID != nil {
		event = event.WithMetadata("command_id", binding.CommandID.String())
	}

	if mode == sensorresult.ModeWarn {
		metrics.SensorUnsolicitedResultsTotal.WithLabelValues("out_of_contract_warned").Inc()
		s.logger.Warn("sensor report carries asset types its tool does not produce; applied (tenant mode warn)",
			"sensor_id", agt.ID.String(), "tenant_id", tenantID.String(), "tool", tool,
			"assets", sp.heldCount(), "report_id", sanitizeIngestLogField(report.Metadata.ID))
		s.auditAsync(auditapp.AuditContext{TenantID: tenantID.String()},
			event.WithMessage(fmt.Sprintf("Sensor report applied with %d asset(s) of types its tool does not produce (warn mode)", sp.heldCount())))
		return report
	}

	quarantineID := ""
	if s.results != nil {
		payload, err := json.Marshal(sp.held)
		if err == nil {
			item := &sensorresult.Item{
				TenantID: tenantID, SensorID: agt.ID, SensorType: string(s.sensorTypeOf(ctx, agt)),
				Protocol: sensorresult.ProtocolV1, Route: opts.Route, ReportID: report.Metadata.ID,
				Reason: sensorresult.ReasonOutOfContract, Payload: payload,
				AssetsCount: len(sp.held.Assets), FindingsCount: len(sp.held.Findings), ToolName: tool,
			}
			if err = s.results.Create(ctx, item, s.resultLimits); err == nil {
				quarantineID = item.ID.String()
			}
		}
		if err != nil {
			s.logger.Warn("out-of-contract assets dropped: they could not be quarantined",
				"sensor_id", agt.ID.String(), "tenant_id", tenantID.String(), "error", err)
		}
	}
	metrics.SensorUnsolicitedResultsTotal.WithLabelValues("out_of_contract_quarantined").Inc()
	s.logger.Info("sensor report: asset types its tool does not produce were held for review",
		"sensor_id", agt.ID.String(), "tenant_id", tenantID.String(), "tool", tool,
		"assets", sp.heldCount(), "findings", sp.heldFindings, "quarantine_id", quarantineID)
	s.auditAsync(auditapp.AuditContext{TenantID: tenantID.String()},
		event.WithMetadata("quarantine_id", quarantineID).
			WithMessage(fmt.Sprintf("%d asset(s) of types the tool does not produce were held for review, not applied", sp.heldCount())))
	return sp.kept
}
