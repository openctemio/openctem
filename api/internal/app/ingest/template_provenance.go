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

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// contentNucleiTemplates is the content name of the nuclei template release
// (sdk-go core.ContentNucleiTemplates).
const contentNucleiTemplates = "nuclei-templates"

// reportTemplateRelease returns the version and digest of the nuclei
// template release a report's tool scanned with (tool.properties.content),
// or empty strings.
func reportTemplateRelease(tool *ctis.Tool) (version, digest string) {
	if tool == nil || tool.Properties == nil {
		return "", ""
	}
	items, ok := tool.Properties["content"].([]any)
	if !ok {
		return "", ""
	}
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if name, _ := m["name"].(string); name != contentNucleiTemplates {
			continue
		}
		version, _ = m["version"].(string)
		digest, _ = m["digest"].(string)
		return version, digest
	}
	return "", ""
}

// findingTemplateProvenance is the sanitized provenance of one finding of a
// report; Empty when the finding names no template digest.
func findingTemplateProvenance(f *ctis.Finding, tool *ctis.Tool) vulnerability.TemplateProvenance {
	if f == nil || f.Properties == nil {
		return vulnerability.TemplateProvenance{}
	}
	p := vulnerability.TemplateProvenance{}
	p.TemplateDigest, _ = f.Properties["template_digest"].(string)
	p.TemplatePath, _ = f.Properties["template_path"].(string)
	p.TemplatesVersion, p.TemplatesDigest = reportTemplateRelease(tool)
	return p.Sanitize()
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
