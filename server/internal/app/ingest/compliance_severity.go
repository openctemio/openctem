package ingest

import (
	"context"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// complianceFactsReader reads the asset facts of the compliance severity
// (postgres.FindingRepository). Optional: without it compliance findings
// keep the scanner's severity.
type complianceFactsReader interface {
	ComplianceAssetFacts(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]vulnerability.ComplianceAssetFact, error)
}

// applyComplianceSeverity gives each compliance finding of the batch its
// compliance severity (benchmark level, asset criticality, environment)
// before it is classified and written, so the scanner's severity never
// drives its priority or deadline (docs/architecture/compliance-checks.md,
// "Priority"). The scanner's severity is kept on the check state and in
// the sighting's source data. One tenant-pinned query per batch.
func (p *FindingProcessor) applyComplianceSeverity(ctx context.Context, tenantID shared.ID, batches ...[]*vulnerability.Finding) {
	var ids []shared.ID
	seen := map[shared.ID]bool{}
	for _, fs := range batches {
		for _, f := range fs {
			if f != nil && f.FindingType() == vulnerability.FindingTypeCompliance && !seen[f.AssetID()] {
				seen[f.AssetID()] = true
				ids = append(ids, f.AssetID())
			}
		}
	}
	if len(ids) == 0 {
		return
	}
	facts := map[shared.ID]vulnerability.ComplianceAssetFact{}
	if r, ok := p.repo.(complianceFactsReader); ok {
		m, err := r.ComplianceAssetFacts(ctx, tenantID, ids)
		if err != nil {
			// Without the facts the level alone decides (never higher).
			p.logger.Warn("compliance asset facts failed", "error", err)
		} else {
			facts = m
		}
	}
	for _, fs := range batches {
		for _, f := range fs {
			if f != nil {
				f.ApplyComplianceSeverity(facts[f.AssetID()])
			}
		}
	}
}
