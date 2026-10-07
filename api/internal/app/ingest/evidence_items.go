package ingest

import (
	"context"
	"encoding/json"

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

// findingEvidence is a sighting's evidence: the CTIS 1.6 evidence_items
// a tool sent (any tool, any kind; an unknown kind is kept as text), or,
// from tools that predate them, the HTTP exchange, extracted values and
// reproduction command attached as properties (the nuclei sensor). A secret
// finding keeps none: its evidence is the leaked value itself, which the
// secret pipeline handles.
func findingEvidence(fingerprint string, cf *ctis.Finding, tool *ctis.Tool) (evidenceapp.Detection, bool) {
	if cf == nil || cf.Type == ctis.FindingTypeSecret || cf.Secret != nil {
		return evidenceapp.Detection{}, false
	}
	if len(cf.EvidenceItems) == 0 && len(cf.Properties) == 0 {
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
	items := typedEvidence(cf.EvidenceItems)
	if len(items) == 0 {
		items = evidencedom.FromToolProperties(cf.Properties, matchedAt, label)
	}
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

// typedEvidence reads CTIS evidence items into the platform's model (the same
// JSON shape), at most evidence.MaxItemsPerReport. An item the platform
// cannot read is skipped; the platform's caps and masking apply later.
func typedEvidence(in []ctis.EvidenceItem) []evidencedom.Item {
	out := make([]evidencedom.Item, 0, min(len(in), evidencedom.MaxItemsPerReport))
	for i := range in {
		if len(out) >= evidencedom.MaxItemsPerReport {
			break
		}
		raw, err := json.Marshal(in[i])
		if err != nil {
			continue
		}
		if it, ok := evidencedom.Decode(raw); ok {
			out = append(out, it)
		}
	}
	return out
}
