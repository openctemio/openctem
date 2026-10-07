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
// A tool the catalog does not know (a tenant's custom tool) has no catalog
// contract.
//
// A tool ported to the tool contract (sdk-go docs/rfcs/sensor-sdk-v2.md)
// also declares what it produces ("asset:<type>", "finding:<type>",
// "dependency") in its sensor's current manifest (tools[].contract). That
// declaration narrows the binding further: an asset, a finding or a
// dependency of a type the tool does not declare is out of contract too. It
// only narrows, never widens: the declaration comes from the sensor, so an
// asset must pass both the catalog (where it knows the tool) and the
// declaration. The declaration is read from the manifest of the sensor that
// submitted the report, scoped to that sensor's tenant: another tenant's
// sensor never contributes one. A sensor without contracts is checked as
// before.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

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

// ToolContractSource reads a sensor's current manifest, where tools ported
// to the tool contract declare what they produce (sensor.ManifestStore).
type ToolContractSource interface {
	CurrentManifest(ctx context.Context, tenantID *shared.ID, sensorID shared.ID) (*sensor.ManifestVersion, error)
}

// SetToolContractSource wires the sensors' manifests, so a ported tool's
// declared produces narrow its reports (nil: the catalog contract only).
func (s *Service) SetToolContractSource(src ToolContractSource) {
	s.contracts = src
}

// declaredContract returns the tool contract the submitting sensor's current
// manifest names for tool, or nil (no manifest, no contract, or an error:
// then only the catalog contract applies, the behavior before contracts).
func (s *Service) declaredContract(ctx context.Context, agt *sensor.Sensor, tool string) *sensor.ToolContract {
	if s.contracts == nil || agt == nil || agt.ID.IsZero() || tool == "" {
		return nil
	}
	v, err := s.contracts.CurrentManifest(ctx, agt.TenantID, agt.ID)
	if err != nil {
		if !errors.Is(err, shared.ErrNotFound) {
			s.logger.Warn("ingest: could not read the sensor manifest for its tool contract",
				"sensor_id", agt.ID.String(), "error", err)
		}
		return nil
	}
	return v.Manifest.ToolContract(tool)
}

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
	kept, held       *ctis.Report
	heldTypes        map[string]int // type label -> assets out of contract
	heldFindings     int
	heldDependencies int
	heldAssetRefs    map[string]bool
}

// outputRules are what a report of one tool may carry: the catalog stages
// (nil: the catalog does not know the tool) and the tool's declared contract
// (nil: none). Both apply when both exist.
type outputRules struct {
	stages   []stage.Stage
	declared *sensor.ToolContract
}

func (r outputRules) empty() bool { return len(r.stages) == 0 && r.declared == nil }

// assetAllowed reports whether the asset is in contract; label names its
// type for the summary when it is not.
func (r outputRules) assetAllowed(a *ctis.Asset) (bool, string) {
	rt := resolveCTISAssetType(a).stored
	ref := asset.TypeRef{Type: rt.Type, SubType: rt.SubType}
	if len(r.stages) > 0 && (rt.Type == asset.AssetTypeUnclassified || !inContract(r.stages, ref)) {
		return false, stage.Label(ref)
	}
	if r.declared != nil && !r.declared.Declares(sensor.ProduceAsset, string(a.Type)) {
		return false, sensor.ProduceAsset + ":" + sanitizeContractLabel(string(a.Type))
	}
	return true, ""
}

func (r outputRules) findingAllowed(f *ctis.Finding) bool {
	return r.declared == nil || r.declared.Declares(sensor.ProduceFinding, string(f.Type))
}

func (r outputRules) dependenciesAllowed() bool {
	return r.declared == nil || r.declared.Declares(sensor.ProduceDependency, "")
}

// sanitizeContractLabel bounds a report-supplied type for logs and audit.
func sanitizeContractLabel(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.ToLower(strings.TrimSpace(v)))
	if len(v) > 64 {
		v = v[:64]
	}
	if v == "" {
		return "(none)"
	}
	return v
}

// splitByContract divides a report into what its tool's contract allows and
// what it does not: the out-of-contract assets, the findings that name them
// or whose type is not declared, and undeclared dependencies. The input
// report is not changed.
func splitByContract(report *ctis.Report, rules outputRules) *contractSplit {
	sp := &contractSplit{heldTypes: map[string]int{}, heldAssetRefs: map[string]bool{}}
	keptAssets := make([]ctis.Asset, 0, len(report.Assets))
	var heldAssets []ctis.Asset
	for i := range report.Assets {
		a := report.Assets[i]
		if ok, label := rules.assetAllowed(&a); !ok {
			heldAssets = append(heldAssets, a)
			sp.heldTypes[label]++
			if a.ID != "" {
				sp.heldAssetRefs[a.ID] = true
			}
			continue
		}
		keptAssets = append(keptAssets, a)
	}
	keptFindings := make([]ctis.Finding, 0, len(report.Findings))
	var heldFindings []ctis.Finding
	for i := range report.Findings {
		f := report.Findings[i]
		if (f.AssetRef != "" && sp.heldAssetRefs[f.AssetRef]) || !rules.findingAllowed(&f) {
			heldFindings = append(heldFindings, f)
			if !rules.findingAllowed(&f) {
				sp.heldTypes[sensor.ProduceFinding+":"+sanitizeContractLabel(string(f.Type))]++
			}
			continue
		}
		keptFindings = append(keptFindings, f)
	}
	keptDeps, heldDeps := report.Dependencies, []ctis.Dependency(nil)
	if len(report.Dependencies) > 0 && !rules.dependenciesAllowed() {
		keptDeps, heldDeps = nil, report.Dependencies
		sp.heldTypes[sensor.ProduceDependency] += len(heldDeps)
	}
	if len(heldAssets) == 0 && len(heldFindings) == 0 && len(heldDeps) == 0 {
		return sp
	}
	kept := *report
	kept.Assets, kept.Findings, kept.Dependencies = keptAssets, keptFindings, keptDeps
	held := *report
	held.Assets, held.Findings, held.Dependencies = heldAssets, heldFindings, heldDeps
	sp.kept, sp.held = &kept, &held
	sp.heldFindings, sp.heldDependencies = len(heldFindings), len(heldDeps)
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

// heldCount is the assets held.
func (sp *contractSplit) heldCount() int {
	if sp.held == nil {
		return 0
	}
	return len(sp.held.Assets)
}

// anyHeld reports whether anything (assets, findings, dependencies) is held.
func (sp *contractSplit) anyHeld() bool {
	return sp.held != nil
}

// bindOutputTypes applies the output-type contract to a command-bound
// sensor report and returns the report to apply. In quarantine mode the
// out-of-contract part is stored for review (never applied, even when the
// quarantine cannot take it); in warn mode the report is applied whole.
func (s *Service) bindOutputTypes(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID, binding Binding,
	report *ctis.Report, opts Options,
) *ctis.Report {
	if report != nil && binding.Kind != BindingCommand {
		// Only a command binds a report to a capability; a claim alone
		// never drives capability-specific handling.
		report.Metadata.Capability = ""
	}
	if binding.Kind != BindingCommand || report == nil ||
		(len(report.Assets) == 0 && len(report.Findings) == 0 && len(report.Dependencies) == 0) {
		return report
	}
	tool := binding.Tool
	if tool == "" && report.Tool != nil {
		tool = report.Tool.Name
	}
	rules := outputRules{stages: outputContract(tool), declared: s.declaredContract(ctx, agt, tool)}
	// The capability the report answers is the platform's, from the
	// command's tool: the sensor's metadata.capability is only a hint.
	report.Metadata.Capability = boundCapability(rules, report.Metadata.Capability)
	s.checkCapabilityContract(agt, tenantID, tool, report)
	if rules.empty() {
		return report // no contract: a tool the catalog does not know, without a declaration
	}
	sp := splitByContract(report, rules)
	if !sp.anyHeld() {
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
		WithMetadata("out_of_contract_dependencies", sp.heldDependencies).
		WithMetadata("declared_contract", rules.declared != nil).
		WithMetadata("types", sp.typeSummary()).
		WithMetadata("mode", string(mode))
	if binding.CommandID != nil {
		event = event.WithMetadata("command_id", binding.CommandID.String())
	}

	if mode == sensorresult.ModeWarn {
		metrics.SensorUnsolicitedResultsTotal.WithLabelValues("out_of_contract_warned").Inc()
		s.logger.Warn("sensor report carries output types its tool does not produce; applied (tenant mode warn)",
			"sensor_id", agt.ID.String(), "tenant_id", tenantID.String(), "tool", sanitizeIngestLogField(tool),
			"assets", sp.heldCount(), "findings", sp.heldFindings, "dependencies", sp.heldDependencies,
			"report_id", sanitizeIngestLogField(report.Metadata.ID))
		s.auditAsync(auditapp.AuditContext{TenantID: tenantID.String()},
			event.WithMessage(fmt.Sprintf("Sensor report applied with %d asset(s), %d finding(s) and %d dependency(ies) its tool does not produce (warn mode)",
				sp.heldCount(), sp.heldFindings, sp.heldDependencies)))
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
			s.logger.Warn("out-of-contract output dropped: it could not be quarantined",
				"sensor_id", agt.ID.String(), "tenant_id", tenantID.String(), "error", err)
		}
	}
	metrics.SensorUnsolicitedResultsTotal.WithLabelValues("out_of_contract_quarantined").Inc()
	s.logger.Info("sensor report: output types its tool does not produce were held for review",
		"sensor_id", agt.ID.String(), "tenant_id", tenantID.String(), "tool", sanitizeIngestLogField(tool),
		"assets", sp.heldCount(), "findings", sp.heldFindings, "dependencies", sp.heldDependencies, "quarantine_id", quarantineID)
	s.auditAsync(auditapp.AuditContext{TenantID: tenantID.String()},
		event.WithMetadata("quarantine_id", quarantineID).
			WithMessage(fmt.Sprintf("%d asset(s), %d finding(s) and %d dependency(ies) of types the tool does not produce were held for review, not applied",
				sp.heldCount(), sp.heldFindings, sp.heldDependencies)))
	return sp.kept
}
