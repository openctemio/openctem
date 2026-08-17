package reclassify

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/api/internal/infra/controller"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// PriorityClassifier is the narrow surface the reclassifier needs
// from PriorityClassificationService. Narrow to keep tests cheap.
type PriorityClassifier interface {
	ClassifyFinding(ctx context.Context, tenantID shared.ID, finding *vulnerability.Finding, a *asset.Asset) error
}

// SLARecomputer recomputes a finding's SLA deadline from its (possibly just
// escalated) priority class. Implemented by *sla.Applier. When a sweep moves a
// finding to a higher priority — e.g. a CVE newly listed in KEV → P0 — the SLA
// deadline must tighten to match; without this the deadline stays at the
// laxer, pre-escalation value and escalation never fires on time.
type SLARecomputer interface {
	ApplyBatch(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) error
}

// Reclassifier implements controller.Reclassifier. It turns a scope
// (AssetIDs, CVEIDs) into concrete Finding+Asset pairs and delegates
// to the classifier. The classifier already handles priority_changed
// event emission via its attached publisher — so a sweep that
// re-confirms the same class is silent, and a sweep that moves a
// class fans out correctly.
//
// Two scopes are handled:
//   - AssetIDs non-empty → reclassify exactly those assets (control-change
//     and asset-change publishers).
//   - AssetIDs empty → whole-tenant sweep: list the tenant's open findings,
//     collect their distinct assets, and reclassify each. This is what the
//     KEV/EPSS-refresh producers (which enqueue per-tenant with no AssetIDs)
//     and the periodic sweep producer rely on.
type Reclassifier struct {
	findings   vulnerability.FindingRepository
	assets     asset.Repository
	classifier PriorityClassifier
	sla        SLARecomputer // optional: recompute sla_deadline on escalation
	logger     *logger.Logger
	// Page size for ListByAssetID. 500 is enough for ~99% of assets
	// while keeping memory bounded.
	perPage int
}

// SetSLARecomputer wires the SLA-deadline recomputer used after a finding is
// reclassified, so an escalation (e.g. new KEV listing → P0) tightens the
// deadline. Optional: nil → deadlines are left unchanged by the sweep.
func (r *Reclassifier) SetSLARecomputer(s SLARecomputer) {
	r.sla = s
}

// NewReclassifier wires deps.
func NewReclassifier(
	findings vulnerability.FindingRepository,
	assets asset.Repository,
	classifier PriorityClassifier,
	log *logger.Logger,
) *Reclassifier {
	if log == nil {
		log = logger.NewNop()
	}
	return &Reclassifier{
		findings:   findings,
		assets:     assets,
		classifier: classifier,
		logger:     log.With("component", "reclassifier"),
		perPage:    500,
	}
}

// ReclassifyForRequest satisfies controller.Reclassifier.
//
// Strategy:
//  1. If req.AssetIDs is non-empty → iterate each asset, page findings,
//     classify. This is the control-change / asset-change path.
//  2. Otherwise → treat as a whole-tenant sweep: page the tenant's open
//     findings, collect their distinct asset IDs, and reclassify each.
//     This is the KEV/EPSS-refresh and periodic-sweep path.
func (r *Reclassifier) ReclassifyForRequest(
	ctx context.Context,
	req controller.ReclassifyRequest,
) (int, error) {
	if r.findings == nil || r.assets == nil || r.classifier == nil {
		return 0, nil
	}

	if len(req.AssetIDs) == 0 {
		// Whole-tenant sweep: no explicit asset scope, so derive it from the
		// tenant's currently-open findings. Producers that can't cheaply name
		// the affected assets (KEV/EPSS refresh, periodic backfill) enqueue
		// this shape.
		return r.reclassifyTenant(ctx, req.TenantID)
	}

	reexamined := 0
	var firstErr error
	for _, assetID := range req.AssetIDs {
		if ctx.Err() != nil {
			return reexamined, ctx.Err()
		}
		n, err := r.reclassifyAsset(ctx, req.TenantID, assetID)
		reexamined += n
		if err != nil {
			// Don't abort the batch — a missing asset shouldn't block
			// the other slots. Surface the first error so the
			// controller can log it at Warn.
			if firstErr == nil {
				firstErr = fmt.Errorf("asset %s: %w", assetID.String(), err)
			}
			continue
		}
	}
	return reexamined, firstErr
}

// reclassifyTenant handles a whole-tenant request (empty AssetIDs). It pages
// the tenant's open findings, accumulates their distinct asset IDs into a set,
// then reclassifies each asset via the same reclassifyAsset path the scoped
// branch uses. Findings with no asset (NULL asset_id — a known separate gap)
// cannot be reclassified through the asset-enrichment path and are counted +
// logged, not classified.
func (r *Reclassifier) reclassifyTenant(
	ctx context.Context,
	tenantID shared.ID,
) (int, error) {
	filter := vulnerability.FindingFilter{
		TenantID: &tenantID,
		// Non-terminal only: mirror FindingStatus.IsClosed so resolved /
		// false_positive / accepted / duplicate / verified / accepted_risk
		// rows are not re-classified.
		ExcludeStatuses: vulnerability.ClosedFindingStatuses(),
	}
	opts := vulnerability.FindingListOptions{}
	page := pagination.Pagination{Page: 1, PerPage: r.perPage}

	seen := make(map[shared.ID]struct{})
	assetIDs := make([]shared.ID, 0)
	skippedNoAsset := 0

	// Phase 1: page findings, collect distinct asset IDs. Bounded memory —
	// only the distinct asset-ID set is retained, not the findings.
	for {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		res, err := r.findings.List(ctx, filter, opts, page)
		if err != nil {
			return 0, fmt.Errorf("list tenant findings: %w", err)
		}
		if len(res.Data) == 0 {
			break
		}
		for _, f := range res.Data {
			aid := f.AssetID()
			if aid.IsZero() {
				skippedNoAsset++
				continue
			}
			if _, ok := seen[aid]; ok {
				continue
			}
			seen[aid] = struct{}{}
			assetIDs = append(assetIDs, aid)
		}
		if int64(len(res.Data)) < int64(page.PerPage) {
			break
		}
		page.Page++
	}

	if skippedNoAsset > 0 {
		r.logger.Debug("whole-tenant sweep skipped findings with no asset",
			"tenant_id", tenantID.String(),
			"skipped", skippedNoAsset,
		)
	}

	// Phase 2: reclassify each distinct asset. Respect cancellation between
	// assets so a tick deadline stops the sweep cleanly.
	reexamined := 0
	var firstErr error
	for _, assetID := range assetIDs {
		if ctx.Err() != nil {
			return reexamined, ctx.Err()
		}
		n, err := r.reclassifyAsset(ctx, tenantID, assetID)
		reexamined += n
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("asset %s: %w", assetID.String(), err)
		}
	}
	return reexamined, firstErr
}

func (r *Reclassifier) reclassifyAsset(
	ctx context.Context,
	tenantID, assetID shared.ID,
) (int, error) {
	// Load asset once per request; enrichment context is the same for
	// every finding on that asset.
	a, err := r.assets.GetByID(ctx, tenantID, assetID)
	if err != nil {
		// Asset gone → treat as soft-miss. Findings on a deleted asset
		// will be cleaned by lifecycle jobs; nothing to reclassify.
		if errors.Is(err, shared.ErrNotFound) {
			return 0, nil
		}
		return 0, fmt.Errorf("load asset: %w", err)
	}

	page := pagination.Pagination{Page: 1, PerPage: r.perPage}
	opts := vulnerability.FindingListOptions{}
	reexamined := 0

	for {
		res, err := r.findings.ListByAssetID(ctx, tenantID, assetID, opts, page)
		if err != nil {
			return reexamined, fmt.Errorf("list findings: %w", err)
		}
		if len(res.Data) == 0 {
			break
		}
		for _, f := range res.Data {
			if ctx.Err() != nil {
				return reexamined, ctx.Err()
			}
			if err := r.classifier.ClassifyFinding(ctx, tenantID, f, a); err != nil {
				r.logger.Warn("classify finding failed in sweep",
					"finding_id", f.ID().String(),
					"error", err,
				)
				continue
			}
			// Recompute the SLA deadline from the (possibly escalated) priority
			// class before persisting, so a KEV/EPSS-driven bump tightens the
			// deadline. Best-effort: a failure keeps the reclassification.
			if r.sla != nil {
				if err := r.sla.ApplyBatch(ctx, tenantID, []*vulnerability.Finding{f}); err != nil {
					r.logger.Warn("sla recompute failed in sweep",
						"finding_id", f.ID().String(),
						"error", err,
					)
				}
			}
			if err := r.findings.Update(ctx, f); err != nil {
				r.logger.Warn("persist reclassified finding failed",
					"finding_id", f.ID().String(),
					"error", err,
				)
				continue
			}
			reexamined++
		}
		// End-of-page when returned count is less than requested.
		if int64(len(res.Data)) < int64(page.PerPage) {
			break
		}
		page.Page++
	}
	return reexamined, nil
}
