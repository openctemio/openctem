package ingest

import (
	"context"
	"encoding/json"

	"github.com/openctemio/ctis/v2"

	evidenceapp "github.com/openctemio/openctem/server/internal/app/evidence"
	evidencedom "github.com/openctemio/openctem/server/pkg/domain/evidence"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
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

// findingEvidence is a sighting's evidence: the evidence_items a tool sent
// (any tool, any kind; an unknown kind is kept as text). properties carry no
// meaning in CTIS 2.0, so nothing is read from them. A secret finding keeps
// none: its evidence is the leaked value itself, which the secret pipeline
// handles.
func findingEvidence(fingerprint string, cf *ctis.Finding, report *ctis.Report) (evidenceapp.Detection, bool) {
	if cf == nil || cf.Type == ctis.FindingTypeSecret || cf.Secret != nil || len(cf.EvidenceItems) == 0 {
		return evidenceapp.Detection{}, false
	}
	items := typedEvidence(cf.EvidenceItems)
	if len(items) == 0 {
		return evidenceapp.Detection{}, false
	}
	prov := findingTemplateProvenance(cf, report)
	toolName := ""
	if report != nil && report.Tool != nil {
		toolName = report.Tool.Name
	}
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

// webLocationFallback gives a CTIS 1.6 web finding (finding.web, no
// location) its URL as the location path, where a pre-1.6 report put the
// matched-at. The finding's endpoint is what a retest re-checks and must
// prove it requested (RFC-057 R2), and the fingerprint of a re-sighting
// stays the one an older report produced. The URL is the redacted one (no
// query values, user info or fragment).
func webLocationFallback(f *ctis.Finding) {
	if f == nil || f.Web == nil || f.Web.URL == "" {
		return
	}
	if f.Location != nil && f.Location.Path != "" {
		return
	}
	if f.Location == nil {
		f.Location = &ctis.FindingLocation{}
	}
	f.Location.Path = f.Web.URL
}
