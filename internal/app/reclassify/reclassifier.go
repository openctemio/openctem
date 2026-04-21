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

// Reclassifier implements controller.Reclassifier. It turns a scope
// (AssetIDs, CVEIDs) into concrete Finding+Asset pairs and delegates
// to the classifier. The classifier already handles priority_changed
// event emission via its attached publisher — so a sweep that
// re-confirms the same class is silent, and a sweep that moves a
// class fans out correctly.
//
// The current impl handles the most-common sweep scope: AssetIDs
// (produced by control-change and asset-change publishers). A CVEIDs
// branch (produced by EPSS/KEV refreshes) is a follow-up — the threat
// intel flow already enqueues with CVEIDs, so this branch will be
// added alongside the next wire of that producer.
type Reclassifier struct {
	findings   vulnerability.FindingRepository
	assets     asset.Repository
	classifier PriorityClassifier
	logger     *logger.Logger
	// Page size for ListByAssetID. 500 is enough for ~99% of assets
	// while keeping memory bounded.
	perPage int
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
//  2. Otherwise → no-op with a warn (we only drain scoped requests for
//     now; unscoped "reclassify everything" would be a footgun without
//     a rate limiter).
func (r *Reclassifier) ReclassifyForRequest(
	ctx context.Context,
	req controller.ReclassifyRequest,
) (int, error) {
	if r.findings == nil || r.assets == nil || r.classifier == nil {
		return 0, nil
	}

	if len(req.AssetIDs) == 0 {
		// CVE-scoped / rule-scoped sweeps are not handled yet — the
		// producers for those paths (EPSS/KEV refresh) haven't been
		// rewired to enqueue. Log once so we notice if someone starts
		// emitting unscoped requests.
		r.logger.Debug("reclassify request has no AssetIDs; skipping",
			"tenant_id", req.TenantID.String(),
			"reason", string(req.Reason),
		)
		return 0, nil
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
