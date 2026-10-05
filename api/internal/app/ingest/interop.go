package ingest

// Source interoperability data at ingest (CTIS 1.4, ctis spec section 4.10).
//
// A report may carry, next to the normalized finding, what its source knew:
// the native identity (plugin ID, QID, rule, native severity and status,
// detection type, credentialed flag), every score with its source, typed
// vulnerability ids, the source lifecycle, solution metadata, a VEX statement
// and unmapped source fields. Ingest:
//
//   - fills the normalized members a report left empty from the typed ones
//     (fillFromInterop), so the server identity recipes (RFC-043) key a
//     finding on its CVE or the source's check id even when the producer only
//     sent them in the new members; a report that sets cve_id or rule_id keeps
//     exactly the key it had, so no stored fingerprint changes;
//   - stores the interop data per sighting (findings columns of migration
//     001055), for the finding detail view only;
//   - acts on a VEX not_affected statement under INGEST_VEX (off, dry_run by
//     default, enforce), with the same guards as source-asserted resolve: the
//     report is bound to a command assigned to the submitting sensor, the
//     finding is open and not from a human source; it becomes false_positive
//     with the justification as its resolution, and the run is audited.
//
// Threat model: the producer is untrusted (RFC-040). Every value is bounded
// (ctis Validate refused over-limit reports; vulnerability.SanitizeInteropData
// bounds again before storage). The location key is derived here, never
// taken from the report. A hostile sensor could try to close findings with a
// forged VEX statement: that needs enforce mode (an operator opt-in), a
// command assigned to that sensor, and leaves an audit record listing every
// finding it closed. Every write is scoped by tenant.

import (
	"context"
	"strings"

	"github.com/openctemio/ctis"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// fillFromInterop completes the normalized members of f from its CTIS 1.4
// members, only where the producer left them empty:
//
//   - vulnerability.cve_id / cve_ids from vulnerability.ids of type cve;
//   - rule_id from native.vuln_id, else from the preferred non-CVE
//     vulnerability id (GHSA, OSV, vendor) when there is no CVE.
//
// A finding that already names a CVE or a rule keeps them, so its identity
// key does not change.
func fillFromInterop(f *ctis.Finding) {
	if f == nil {
		return
	}
	v := f.Vulnerability
	if v != nil && strings.TrimSpace(v.CVEID) == "" && len(v.CVEIDs) == 0 && len(v.IDs) > 0 {
		var cves []string
		for _, id := range ctis.VulnerabilityIDs(v) {
			if id.Type == ctis.VulnerabilityIDCVE {
				cves = append(cves, id.ID)
			}
		}
		if len(cves) > 0 {
			if p, ok := ctis.PreferredVulnerabilityID(v); ok && p.Type == ctis.VulnerabilityIDCVE {
				v.CVEID = p.ID
			}
			v.CVEIDs = cves
		}
	}
	if strings.TrimSpace(f.RuleID) != "" {
		return
	}
	if f.Native != nil && strings.TrimSpace(f.Native.VulnID) != "" {
		f.RuleID = strings.TrimSpace(f.Native.VulnID)
		return
	}
	if v != nil && strings.TrimSpace(v.CVEID) == "" && len(v.CVEIDs) == 0 {
		if p, ok := ctis.PreferredVulnerabilityID(v); ok {
			f.RuleID = p.ID
		}
	}
}

// interopUpdate is a sighting's interop data. Scores include the legacy
// single-valued members (ctis.AllScores), so the detail view shows one list
// whatever minor the producer wrote.
func interopUpdate(fingerprint string, f *ctis.Finding) vulnerability.InteropUpdate {
	u := vulnerability.InteropUpdate{Fingerprint: fingerprint}
	d := &u.Data
	if n := f.Native; n != nil {
		d.Native = &vulnerability.InteropNative{
			Scheme: string(n.Scheme), VulnID: n.VulnID, InstanceID: n.InstanceID, Family: n.Family,
			Severity: n.Severity, Status: n.Status, DetectionType: string(n.DetectionType),
			Credentialed: n.Credentialed, RawRef: n.RawRef,
		}
	}
	for _, s := range ctis.AllScores(f) {
		d.Scores = append(d.Scores, vulnerability.InteropScore{
			System: string(s.System), Version: s.Version, Vector: s.Vector, Value: s.Value,
			Label: s.Label, Source: s.Source, AsOf: s.AsOf,
		})
	}
	for _, id := range ctis.VulnerabilityIDs(f.Vulnerability) {
		d.VulnerabilityIDs = append(d.VulnerabilityIDs, vulnerability.InteropVulnID{Type: string(id.Type), ID: id.ID, Source: id.Source})
	}
	if l := f.SourceLifecycle; l != nil {
		d.Lifecycle = &vulnerability.InteropLifecycle{
			FirstFound: l.FirstFound, LastFound: l.LastFound, LastFixed: l.LastFixed,
			TimesFound: l.TimesFound, State: string(l.State),
		}
	}
	if r := f.Remediation; r != nil && (r.SolutionType != "" || r.PatchPublishedAt != nil || len(r.Advisories) > 0) {
		s := &vulnerability.InteropSolution{Type: string(r.SolutionType), PatchPublishedAt: r.PatchPublishedAt}
		for _, a := range r.Advisories {
			s.Advisories = append(s.Advisories, vulnerability.InteropAdvisory{ID: a.ID, URL: a.URL, Source: a.Source})
		}
		d.Solution = s
	}
	if x := f.VEX; x != nil {
		d.VEX = &vulnerability.InteropVEX{
			Status: string(x.Status), Justification: string(x.Justification),
			NativeJustification: x.NativeJustification, Statement: x.Statement, Source: x.Source, AsOf: x.AsOf,
		}
	}
	if len(f.SourceExtra) > 0 {
		d.SourceExtra = make(map[string]string, len(f.SourceExtra))
		for k, v := range f.SourceExtra {
			d.SourceExtra[k] = v
		}
	}
	d.LocationKey = ctis.LocationKey(f)
	u.Data = vulnerability.SanitizeInteropData(u.Data)
	return u
}

// interopWriter stores interop data by fingerprint (postgres.FindingRepository).
// Optional: a repository without it keeps none.
type interopWriter interface {
	UpdateInteropBatch(ctx context.Context, tenantID shared.ID, updates []vulnerability.InteropUpdate) (int64, error)
}

// vexApplier closes findings a VEX not_affected statement covers
// (postgres.FindingRepository). Optional: without it VEX is stored only.
type vexApplier interface {
	ApplyVEXNotAffected(ctx context.Context, tenantID shared.ID, items []vulnerability.VEXNotAffected, dryRun bool) ([]shared.ID, error)
}

// storeInterop writes each sighting's interop data. Best effort: a failure
// is logged and never fails the ingest.
func (p *FindingProcessor) storeInterop(ctx context.Context, tenantID shared.ID, updates []vulnerability.InteropUpdate) {
	w, ok := p.repo.(interopWriter)
	if !ok || len(updates) == 0 {
		return
	}
	if _, err := w.UpdateInteropBatch(ctx, tenantID, updates); err != nil {
		p.logger.Warn("failed to store finding interop data", "error", err, "count", len(updates))
	}
}

// VEXMode is how ingest acts on a VEX not_affected statement.
type VEXMode = SourceResolveMode

// ParseVEXMode reads INGEST_VEX. Anything that is not "off" or "enforce" is
// dry_run: an unknown value must never start closing findings.
func ParseVEXMode(v string) VEXMode { return ParseSourceResolveMode(v) }

// SetVEXMode sets how ingest acts on VEX not_affected statements.
func (s *Service) SetVEXMode(mode VEXMode) {
	s.findingProcessor.vexMode = mode
}

func (p *FindingProcessor) vex() VEXMode {
	if p.vexMode == "" {
		return SourceResolveDryRun
	}
	return p.vexMode
}

// vexSighting is one stored sighting of the report and its CTIS finding.
type vexSighting struct {
	fingerprint string
	assetID     shared.ID
	finding     *ctis.Finding
}

// vexNotAffectedItems are the sightings whose VEX statement says
// not_affected with a reason.
func vexNotAffectedItems(sightings []vexSighting) []vulnerability.VEXNotAffected {
	out := make([]vulnerability.VEXNotAffected, 0, len(sightings))
	for i := range sightings {
		fm := &sightings[i]
		x := fm.finding.VEX
		if x == nil || x.Status != ctis.VEXStatusNotAffected || (x.Justification == "" && strings.TrimSpace(x.Statement) == "") {
			continue
		}
		iv := vulnerability.SanitizeInteropData(vulnerability.InteropData{VEX: &vulnerability.InteropVEX{
			Status: string(x.Status), Justification: string(x.Justification), Statement: x.Statement, Source: x.Source,
		}}).VEX
		if iv == nil {
			continue
		}
		out = append(out, vulnerability.VEXNotAffected{
			Fingerprint: fm.fingerprint,
			AssetID:     fm.assetID.String(),
			Resolution:  vulnerability.VEXResolutionText(iv),
		})
	}
	return out
}

// applyVEX closes (enforce) or counts (dry_run) the open findings the
// report's VEX statements say are not affected.
func (p *FindingProcessor) applyVEX(ctx context.Context, tenantID shared.ID, items []vulnerability.VEXNotAffected, scope *alterScope, output *Output) {
	if len(items) == 0 {
		return
	}
	output.FindingsVEXNotAffected += len(items)
	mode := p.vex()
	if mode == SourceResolveOff || scope == nil || !scope.commandBound {
		return
	}
	repo, ok := p.repo.(vexApplier)
	if !ok {
		return
	}
	ids, err := repo.ApplyVEXNotAffected(ctx, tenantID, items, mode != SourceResolveEnforce)
	if err != nil {
		p.logger.Warn("vex not_affected failed", "tenant_id", tenantID.String(), "error", err)
		addError(output, "vex not_affected failed")
		return
	}
	output.VEXIDs = append(output.VEXIDs, ids...)
	output.VEXMode = mode
	if mode == SourceResolveEnforce {
		output.FindingsVEXClosed += len(ids)
	} else {
		output.FindingsVEXWouldClose += len(ids)
	}
	if len(ids) > 0 {
		p.logger.Info("vex not_affected", "tenant_id", tenantID.String(), "mode", string(mode),
			"findings", len(ids), "statements", len(items))
	}
}

// auditVEX records, once per report, the findings a VEX statement closed
// (enforce) or would have closed (dry_run).
func (s *Service) auditVEX(ctx context.Context, tenantID shared.ID, binding Binding, tool string, out *Output) {
	if len(out.VEXIDs) == 0 || (s.auditSvc == nil && s.auditRepo == nil) {
		return
	}
	action := audit.ActionIngestVEXApplied
	if out.VEXMode != SourceResolveEnforce {
		action = audit.ActionIngestVEXDryRun
	}
	ids := out.VEXIDs
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
	event.Message = "VEX not_affected: the report stated these findings are not affected"
	event.Metadata = map[string]any{
		"mode": string(out.VEXMode), "tool_name": logValue(tool), "count": len(ids),
		"statements":  out.FindingsVEXNotAffected,
		"finding_ids": listed, "finding_ids_truncated": len(ids) > maxAuditedFindingIDs,
	}
	if err := s.writeIngestAuditLog(ctx, auditapp.AuditContext{TenantID: tenantID.String()}, event); err != nil {
		s.logger.Warn("failed to write vex audit log", "error", err)
	}
}

// maxHintLen and maxHintMACs bound stored identity hints (CTIS 1.4 limits).
const (
	maxHintLen  = 255
	maxHintMACs = 32
)

// identityHintProperties is the asset property form of identity hints, every
// value trimmed, stripped of control characters and bounded; nil when empty.
func identityHintProperties(h *ctis.IdentityHints) map[string]any {
	if h == nil {
		return nil
	}
	out := map[string]any{}
	for _, kv := range [][2]string{
		{"fqdn", h.FQDN}, {"netbios_name", h.NetBIOSName}, {"os_cpe", h.OSCPE},
		{"cloud_resource_id", h.CloudResourceID}, {"agent_id", h.AgentID},
	} {
		if c := hintText(kv[1]); c != "" {
			out[kv[0]] = c
		}
	}
	var macs []string
	for _, m := range h.MACAddresses {
		if len(macs) == maxHintMACs {
			break
		}
		if c := hintText(m); c != "" && len(c) <= 64 {
			macs = append(macs, c)
		}
	}
	if len(macs) > 0 {
		out["mac_addresses"] = macs
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func hintText(s string) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "")))
	if r := []rune(s); len(r) > maxHintLen {
		s = string(r[:maxHintLen])
	}
	return s
}
