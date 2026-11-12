package ingest

// Template provenance at ingest (research/18 O6, sensor#134): a nuclei
// finding carries properties.template_digest (sha256 of the template file
// that matched) and properties.template_path; the report's tool carries
// the template release it scanned with in tool.properties.content
// ([{name: "nuclei-templates", version, digest, ...}]). These used to be
// dropped with every unknown finding property. They are kept on the
// finding as its last sighting's baseline (vulnerability.TemplateProvenance)
// for the retest and coverage rules.

import (
	"context"
	"strings"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// contentNucleiTemplates is the content name of the nuclei template release
// (sdk-go core.ContentNucleiTemplates).
const contentNucleiTemplates = "nuclei-templates"

// reportTemplateRelease returns the version and digest of the nuclei
// template release a report's tool scanned with (tool.content), or empty
// strings.
func reportTemplateRelease(tool *ctis.Tool) (version, digest string) {
	if tool == nil {
		return "", ""
	}
	for _, c := range tool.Content {
		if c.Name == contentNucleiTemplates {
			return c.Version, storedDigest(c.SHA256)
		}
	}
	return "", ""
}

// ruleOf is the rule of the report's rule catalog a finding names
// (rule_ref), or nil.
func ruleOf(report *ctis.Report, f *ctis.Finding) *ctis.Rule {
	if report == nil || f == nil || f.RuleRef == "" {
		return nil
	}
	for i := range report.Rules {
		if report.Rules[i].ID == f.RuleRef {
			return &report.Rules[i]
		}
	}
	return nil
}

// findingTemplateProvenance is the sanitized provenance of one finding of a
// report: the content digest and path of the rule it names (rules[] of
// CTIS 2.0), the template release of the report's tool, and whether the
// rule is one of the organization's own; Empty when it names no template
// digest and is not one of the organization's own rules.
func findingTemplateProvenance(f *ctis.Finding, report *ctis.Report) vulnerability.TemplateProvenance {
	if f == nil {
		return vulnerability.TemplateProvenance{}
	}
	p := vulnerability.TemplateProvenance{}
	ruleSource := ""
	if r := ruleOf(report, f); r != nil {
		p.TemplateDigest = storedDigest(r.ContentSHA256)
		if raw := r.ContentPath; raw != "" {
			// A sensor may report the file on its own disk: keep the path
			// inside the template pack only. Any other absolute path (a
			// temporary directory, a workspace) names no pack template and
			// is dropped, not stored as its tail.
			switch n := vulnerability.NormalizeTemplatePath(raw); n.Kind {
			case vulnerability.SensorPathTemplate, vulnerability.SensorPathRelative:
				p.TemplatePath = n.Rel
			}
		}
		if v, ok := r.Extensions.Get(ctis.OpenCTEMNamespace, "rule_source"); ok {
			ruleSource, _ = v.(string)
		}
	}
	if report != nil {
		p.TemplatesVersion, p.TemplatesDigest = reportTemplateRelease(report.Tool)
	}
	// The template's own tags as the sensor reported them at this sighting
	// (not the finding's tags, which a user can edit).
	p.ExposureClass = vulnerability.ExposureTemplateTags(f.Tags)
	// The organization's own rules: the sensor prefixes their ids and marks
	// them (rules[].extensions["io.openctem"].rule_source). The store links
	// the template.
	if ruleSource == vulnerability.RuleSourceTenant || strings.HasPrefix(f.RuleID, vulnerability.TenantRulePrefix) {
		p.RuleSource = vulnerability.RuleSourceTenant
		p.RuleID = f.RuleID
	}
	return p.Sanitize()
}

// sightingProvenance is findingTemplateProvenance for a report received
// under scope. Only a result of a command the platform dispatched may set the
// exposure class: any other ingest (API, CTIS or CI upload) carries tags its
// submitter chose, and the class decides when an access refusal proves a fix.
func sightingProvenance(f *ctis.Finding, report *ctis.Report, scope *alterScope) vulnerability.TemplateProvenance {
	p := findingTemplateProvenance(f, report)
	if scope == nil || !scope.commandBound {
		p.ExposureClass = false
	}
	return p
}

// recordTemplateSightings stores the provenance of the findings a report
// sighted (best effort: a failure is logged and the ingest goes on).
// A finding without a template digest keeps its previous baseline.
func (p *FindingProcessor) recordTemplateSightings(ctx context.Context, tenantID shared.ID, sightings []vulnerability.TemplateSighting) {
	store, ok := p.repo.(vulnerability.TemplateProvenanceStore)
	if !ok || len(sightings) == 0 {
		return
	}
	if n, err := store.RecordTemplateSightings(ctx, tenantID, sightings); err != nil {
		p.logger.Warn("failed to record template provenance", "error", err, "count", len(sightings))
	} else if n > 0 {
		p.logger.Debug("recorded template provenance", "count", n)
	}
}

// storedDigest is the stored form of a CTIS 2.0 sha256 digest: CTIS carries
// the bare lower-case hex, the platform keeps "sha256:<hex>"
// (vulnerability.SanitizeTemplateDigest). "" stays "".
func storedDigest(hex string) string {
	if hex == "" || strings.HasPrefix(hex, "sha256:") {
		return hex
	}
	return "sha256:" + hex
}
