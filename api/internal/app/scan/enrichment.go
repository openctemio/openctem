package scan

// Automatic enrichment runs (docs/architecture/asset-freshness.md): the
// asset-enrichment controller starts a passive run of a built-in profile for
// a batch of asset names. Unlike a person's quick scan, one name that may not
// be scanned never refuses the batch: it is dropped and counted, and the
// run's own gates (passive scope rule, rejected names, scan windows, program
// rules at delivery) still apply to what is left.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EnrichmentTag marks automatic enrichment scans.
const EnrichmentTag = "auto-enrichment"

// maxEnrichmentTargets caps one enrichment run.
const maxEnrichmentTargets = 500

// EnrichmentInput is one batch of one profile.
type EnrichmentInput struct {
	TenantID   shared.ID
	WorkflowID shared.ID
	Targets    []string
}

// EnrichmentResult is what was started. RunID is nil when no target was left.
type EnrichmentResult struct {
	RunID *shared.ID
	// Kept are the targets the run took; Dropped the ones it did not
	// (invalid, internal, outside the system act scope).
	Kept    []string
	Dropped []string
}

// StartEnrichment starts a passive run of a system enrichment workflow for
// the targets, as the system (no member's act scope; scope entries only).
func (s *Service) StartEnrichment(ctx context.Context, in EnrichmentInput) (*EnrichmentResult, error) {
	if in.TenantID.IsZero() || in.WorkflowID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and workflow are required", shared.ErrValidation)
	}
	if len(in.Targets) > maxEnrichmentTargets {
		return nil, fmt.Errorf("%w: at most %d targets per enrichment run", shared.ErrValidation, maxEnrichmentTargets)
	}
	wf, err := s.usableWorkflow(ctx, in.TenantID, in.WorkflowID)
	if err != nil {
		return nil, err
	}
	if !wf.IsSystemTemplate {
		return nil, fmt.Errorf("%w: enrichment runs only system workflows", shared.ErrValidation)
	}
	res := &EnrichmentResult{}
	kept, err := s.enrichmentTargets(ctx, in, res)
	if err != nil {
		return nil, err
	}
	if len(kept) == 0 {
		return res, nil
	}
	res.Kept = kept

	sc, err := scan.NewScan(in.TenantID, fmt.Sprintf("Automatic enrichment - %s", time.Now().UTC().Format("20060102-150405")),
		shared.ID{}, scan.ScanTypeWorkflow)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan: %w", err)
	}
	sc.AdHoc = true
	sc.Description = fmt.Sprintf("Automatic passive enrichment of %d new assets", len(kept))
	sc.SetTargets(kept)
	if err := sc.SetWorkflow(in.WorkflowID); err != nil {
		return nil, fmt.Errorf("failed to set workflow: %w", err)
	}
	sc.SetTags([]string{EnrichmentTag})
	// Each enrichment batch is its own scan; its key is its own id.
	sc.ManagedBy, sc.ManagedKey = scan.ManagedByEnrichment, sc.ID.String()
	if err := s.applyIntensity(ctx, sc, string(scan.IntensityPassive)); err != nil {
		return nil, err
	}
	if err := s.scanRepo.Create(ctx, sc); err != nil {
		return nil, fmt.Errorf("failed to create scan: %w", err)
	}
	run, err := s.TriggerScan(ctx, TriggerScanExecInput{
		TenantID: in.TenantID.String(),
		ScanID:   sc.ID.String(),
		// The run is the enrichment policy's: no person is behind it.
		TriggerType: scanworkflow.TriggerTypeSystem,
		TriggeredBy: PolicyTriggerPrefix + string(scan.ManagedByEnrichment),
		Context:     map[string]any{"trigger": "auto_enrichment", "target_count": len(kept)},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to trigger enrichment: %w", err)
	}
	res.RunID = &run.ID
	return res, nil
}

// enrichmentTargets puts the targets through the one dispatch gate as a
// passive dispatch by the system: target validation (no internal, metadata,
// link-local or malformed names), scope exclusions, the system act scope,
// the passive scope rule (a name no scope authority of the tenant covers is
// refused) and rejected names. What it refuses is dropped, never fatal.
func (s *Service) enrichmentTargets(ctx context.Context, in EnrichmentInput, res *EnrichmentResult) ([]string, error) {
	tier := scopedom.TierPassive
	gated, err := s.ResolveDispatchTargets(ctx, DispatchTargetsInput{
		TenantID:        in.TenantID,
		Targets:         in.Targets,
		SystemPolicy:    string(scan.ManagedByEnrichment),
		PassiveOnly:     true,
		Tier:            &tier,
		SkipZoneRouting: true,
		MaxTargets:      maxEnrichmentTargets,
		Path:            "auto_enrichment",
	})
	if err != nil {
		return nil, fmt.Errorf("enrichment targets not checked, nothing dispatched: %w", err)
	}
	allowed := make(map[string]bool, len(gated.Allowed))
	for _, t := range gated.Allowed {
		allowed[strings.ToLower(t)] = true
	}
	kept := make([]string, 0, len(gated.Allowed))
	for _, t := range in.Targets {
		if allowed[strings.ToLower(strings.TrimSpace(t))] {
			kept = append(kept, strings.TrimSpace(t))
		} else {
			res.Dropped = append(res.Dropped, t)
		}
	}
	return kept, nil
}
