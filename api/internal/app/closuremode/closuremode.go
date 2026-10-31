// Package closuremode is the organization's closing mode in front of every
// writer that closes findings without a person (docs/architecture/
// finding-verification-plan.md, "Closing mode"). A writer sorts the findings
// it would close into close, propose and keep with Split, closes only the
// first group, and records the second with Propose.
package closuremode

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SettingsReader reads an organization's closing policy. The tenant service
// implements it.
type SettingsReader interface {
	GetClosureSettings(ctx context.Context, tenantID string) (*tenant.ClosureSettings, error)
}

// tierReader is implemented by the postgres finding repository.
type tierReader interface {
	FindingRiskTiers(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]vulnerability.RiskTier, error)
}

// Decider applies the closing mode. Settings nil means every organization is
// in review. Repo is the finding repository (risk tiers, proposals).
type Decider struct {
	Settings SettingsReader
	Repo     any
	Log      *logger.Logger
}

// Settings loads the organization's policy. No reader or a read failure is
// review: never closes, still records.
func (d Decider) settings(ctx context.Context, tenantID shared.ID) tenant.ClosureSettings {
	if d.Settings == nil {
		return tenant.ClosureSettings{}
	}
	cs, err := d.Settings.GetClosureSettings(ctx, tenantID.String())
	if err != nil || cs == nil {
		d.Log.Warn("closing mode: could not read the closing mode, using review", "tenant_id", tenantID.String(), "error", err)
		return tenant.ClosureSettings{}
	}
	return *cs
}

// Split sorts the findings a writer would close with the given method into
// close, propose and keep. Off keeps everything (nothing is proposed). The
// tiers are read in one tenant-scoped query; when they cannot be read every
// finding is treated as critical (proposed unless the owner opted in), and
// an id the query does not return (another tenant's, or deleted) is kept.
func (d Decider) Split(ctx context.Context, tenantID shared.ID, ids []shared.ID, method vulnerability.ClosureMethod) (closeIDs, propose, keep []shared.ID) {
	cs := d.settings(ctx, tenantID)
	mode := cs.EffectiveMode()
	if mode == tenant.ClosingModeOff {
		return nil, nil, ids
	}
	var tiers map[shared.ID]vulnerability.RiskTier
	if mode == tenant.ClosingModeAuto {
		var err error
		if tr, ok := d.Repo.(tierReader); ok {
			tiers, err = tr.FindingRiskTiers(ctx, tenantID, ids)
		}
		if err != nil || tiers == nil {
			d.Log.Warn("closing mode: could not read finding tiers, treating them as critical", "tenant_id", tenantID.String(), "error", err)
			tiers = make(map[shared.ID]vulnerability.RiskTier, len(ids))
			for _, id := range ids {
				tiers[id] = vulnerability.RiskTierCritical
			}
		}
	}
	for _, id := range ids {
		tier := vulnerability.RiskTierCritical
		if tiers != nil {
			t, ok := tiers[id]
			if !ok {
				keep = append(keep, id)
				continue
			}
			tier = t
		}
		// No per-asset flaky mark exists yet: flaky is false.
		switch vulnerability.DecideClosure(mode, tier, method, false, cs.CriticalAutoClose) {
		case vulnerability.ClosureDecisionClose:
			closeIDs = append(closeIDs, id)
		case vulnerability.ClosureDecisionPropose:
			propose = append(propose, id)
		default:
			keep = append(keep, id)
		}
	}
	return closeIDs, propose, keep
}

// Record stores the proposals. The decision stands even if recording fails
// (logged): nothing closes either way. A repository without proposal
// support records nothing.
func (d Decider) Record(ctx context.Context, tenantID shared.ID, recs []vulnerability.ClosureProposalRecord) {
	if len(recs) == 0 {
		return
	}
	repo, ok := d.Repo.(vulnerability.ClosureProposalRepository)
	if !ok {
		return
	}
	if _, err := repo.RecordClosureProposals(ctx, tenantID, recs); err != nil {
		d.Log.Warn("closing mode: recording closure proposals failed", "tenant_id", tenantID.String(), "error", err)
	}
}
