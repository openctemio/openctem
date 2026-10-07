package ingest

import (
	"context"

	"github.com/openctemio/ctis"

	evidenceapp "github.com/openctemio/openctem/api/internal/app/evidence"
	evidencedom "github.com/openctemio/openctem/api/pkg/domain/evidence"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EvidenceStore keeps the typed proof of each sighting
// (docs/architecture/finding-evidence.md). Best-effort: it logs its own
// failures and never fails an ingest.
type EvidenceStore interface {
	StoreDetections(ctx context.Context, tenantID shared.ID, dets []evidenceapp.Detection)
}

// SetEvidenceStore wires finding evidence storage. Nil: none is kept.
func (p *FindingProcessor) SetEvidenceStore(s EvidenceStore) { p.evidence = s }

// SetEvidenceStore wires finding evidence storage on the processor.
func (s *Service) SetEvidenceStore(e EvidenceStore) { s.findingProcessor.SetEvidenceStore(e) }

// findingEvidence is a sighting's evidence: the HTTP exchange, extracted
// values and reproduction command a tool attached as properties (the nuclei
// sensor does). A secret finding keeps none: its evidence is the leaked
// value itself, which the secret pipeline handles.
func findingEvidence(fingerprint string, cf *ctis.Finding, tool *ctis.Tool) (evidenceapp.Detection, bool) {
	if cf == nil || cf.Type == ctis.FindingTypeSecret || cf.Secret != nil || len(cf.Properties) == 0 {
		return evidenceapp.Detection{}, false
	}
	matchedAt := ""
	if cf.Location != nil {
		matchedAt = cf.Location.Path
	}
	toolName := ""
	if tool != nil {
		toolName = tool.Name
	}
	label := toolName
	if cf.RuleID != "" {
		label += " " + cf.RuleID
	}
	items := evidencedom.FromToolProperties(cf.Properties, matchedAt, label)
	if len(items) == 0 {
		return evidenceapp.Detection{}, false
	}
	prov := findingTemplateProvenance(cf, tool)
	return evidenceapp.Detection{
		Fingerprint: fingerprint,
		Items:       items,
		Meta:        evidenceapp.Meta{ToolName: toolName, RuleID: cf.RuleID, TemplateDigest: prov.TemplateDigest},
	}, true
}
