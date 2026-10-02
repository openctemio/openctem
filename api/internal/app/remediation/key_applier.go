package remediation

import (
	"context"

	remediationdom "github.com/openctemio/api/pkg/domain/remediation"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// KeyApplier derives each finding's remediation group key and upserts it into
// the side-table. Implements ingest.RemediationKeyApplier. Best-effort — a
// failed key never blocks ingest.
type KeyApplier struct {
	repo   remediationdom.KeyRepository
	logger *logger.Logger
}

// NewKeyApplier constructs a KeyApplier.
func NewKeyApplier(repo remediationdom.KeyRepository, log *logger.Logger) *KeyApplier {
	return &KeyApplier{repo: repo, logger: log.With("component", "remediation_key_applier")}
}

// ApplyBatch derives and upserts a remediation key for each groupable finding.
// Ungroupable findings (no shared fix signal) are skipped.
func (a *KeyApplier) ApplyBatch(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) error {
	for _, f := range findings {
		if f == nil {
			continue
		}
		key, title, ok := remediationdom.DeriveKey(deriveInput(f))
		if !ok {
			continue
		}
		if err := a.repo.Upsert(ctx, tenantID, f.ID(), key, title); err != nil {
			// Best-effort: log and continue so one bad row doesn't drop the batch.
			a.logger.Debug("upsert remediation key failed", "finding_id", f.ID().String(), "error", err)
		}
	}
	return nil
}

// deriveInput extracts the grouping signals from a finding.
func deriveInput(f *vulnerability.Finding) remediationdom.KeyInput {
	in := remediationdom.KeyInput{}

	// SCA: a finding tied to a component groups by that component (one upgrade
	// fixes every finding on the package).
	if cid := f.ComponentID(); cid != nil && !cid.IsZero() {
		in.ComponentKey = cid.String()
	}

	if rem := f.Remediation(); rem != nil {
		in.FixAvailable = rem.FixAvailable
		in.SolutionText = rem.Recommendation
	}
	if in.SolutionText == "" {
		in.SolutionText = f.Recommendation()
	}
	if f.RemedyAvailable() {
		in.FixAvailable = true
	}
	return in
}
