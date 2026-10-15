// Package reclassify recomputes the priority class and SLA deadline of open
// findings from the durable finding-priority queue
// (docs/architecture/scoring-versions.md).
//
// Forward only: a pass reads the open findings of a queued asset, never a
// closed one, so a closed finding keeps the class, reason and deadline it had
// when it was closed and closed-period metrics never change after the fact.
package reclassify

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/scoring"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// PriorityClassifier is the narrow surface the reclassifier needs from
// PriorityClassificationService. The batch path re-reads EPSS and KEV from
// the trusted catalogs, so a pass also applies intel that changed since the
// finding was ingested.
type PriorityClassifier interface {
	EnrichAndClassifyBatch(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding, assets map[shared.ID]*asset.Asset) error
}

// SLARecomputer recomputes a finding's SLA deadline from its (possibly just
// changed) priority class. Implemented by *sla.Applier.
type SLARecomputer interface {
	ApplyBatch(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) error
}

// Defaults of one worker pass.
const (
	DefaultQueueBatch = 200 // assets claimed per pass
	DefaultPerTenant  = 50  // at most this many of one tenant per pass
)

// Reclassifier drains the finding-priority queue.
type Reclassifier struct {
	findings   vulnerability.FindingRepository
	assets     asset.Repository
	classifier PriorityClassifier
	sla        SLARecomputer
	queue      scoring.PriorityQueue
	versions   scoring.VersionRepository
	logger     *logger.Logger
	// Page size for the open findings of one asset.
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

// SetSLARecomputer wires the SLA-deadline recomputer run after a finding is
// reclassified. Optional: nil leaves deadlines unchanged.
func (r *Reclassifier) SetSLARecomputer(s SLARecomputer) {
	r.sla = s
}

// SetQueue wires the durable queue and the version source.
func (r *Reclassifier) SetQueue(q scoring.PriorityQueue, v scoring.VersionRepository) {
	r.queue = q
	r.versions = v
}

// ProcessQueue claims up to limit queued assets (tenant-fair) and
// recomputes their open findings, tenant by tenant. A tenant whose pass
// fails is queued again.
func (r *Reclassifier) ProcessQueue(ctx context.Context, limit, perTenant int) (scoring.QueueResult, error) {
	var res scoring.QueueResult
	if r.queue == nil || r.findings == nil || r.assets == nil || r.classifier == nil {
		return res, nil
	}
	items, err := r.queue.Claim(ctx, limit, perTenant)
	if err != nil {
		return res, err
	}
	res.Claimed = len(items)

	byTenant := make(map[shared.ID][]shared.ID)
	order := make([]shared.ID, 0)
	for _, it := range items {
		if _, ok := byTenant[it.TenantID]; !ok {
			order = append(order, it.TenantID)
		}
		byTenant[it.TenantID] = append(byTenant[it.TenantID], it.AssetID)
	}

	var errs []error
	for _, tid := range order {
		ids := byTenant[tid]
		checked, changed, err := r.ReclassifyAssets(ctx, tid, ids)
		res.Checked += checked
		res.Changed += changed
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", tid, err))
			requeueCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			if qerr := r.queue.EnqueueAssets(requeueCtx, tid, ids, scoring.ReasonFindingChange); qerr != nil {
				errs = append(errs, fmt.Errorf("tenant %s requeue: %w", tid, qerr))
			}
			cancel()
		}
	}
	return res, errors.Join(errs...)
}

// QueueStats returns the queue depth and the oldest due row's age.
func (r *Reclassifier) QueueStats(ctx context.Context) (scoring.QueueStats, error) {
	if r.queue == nil {
		return scoring.QueueStats{}, nil
	}
	return r.queue.Stats(ctx)
}

// EnqueueReconcile queues stale findings now and every other open finding
// after delay.
func (r *Reclassifier) EnqueueReconcile(ctx context.Context, delay time.Duration) (int64, error) {
	if r.queue == nil {
		return 0, nil
	}
	return r.queue.EnqueueReconcile(ctx, delay)
}

// ReclassifyAssets recomputes the open findings of the given assets of the
// tenant and stamps them with the version read before computing: a change
// that lands during the pass leaves an older stamp, so the findings are
// computed again (a stamp is never newer than the inputs it was computed
// with). Returns the findings checked and those whose stored values changed.
func (r *Reclassifier) ReclassifyAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (checked, changed int, err error) {
	var version int64
	if r.versions != nil {
		version, err = r.versions.CurrentVersion(ctx, tenantID, scoring.KindFindingPriority)
		if err != nil {
			return 0, 0, err
		}
	}
	var firstErr error
	for _, assetID := range assetIDs {
		if ctx.Err() != nil {
			return checked, changed, ctx.Err()
		}
		ids, n, err := r.reclassifyAsset(ctx, tenantID, assetID)
		checked += len(ids)
		changed += n
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("asset %s: %w", assetID, err)
			}
			continue
		}
		if r.queue != nil && version > 0 {
			if err := r.queue.StampVersion(ctx, tenantID, ids, version); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return checked, changed, firstErr
}

// reclassifyAsset recomputes the open findings of one asset. It returns the
// ids of the findings it computed (persisted or confirmed unchanged) and how
// many changed.
func (r *Reclassifier) reclassifyAsset(ctx context.Context, tenantID, assetID shared.ID) ([]shared.ID, int, error) {
	a, err := r.assets.GetByID(ctx, tenantID, assetID)
	if err != nil {
		// Asset gone: its findings are cleaned by lifecycle jobs.
		if errors.Is(err, shared.ErrNotFound) {
			return nil, 0, nil
		}
		return nil, 0, fmt.Errorf("load asset: %w", err)
	}
	assets := map[shared.ID]*asset.Asset{a.ID(): a}

	filter := vulnerability.NewFindingFilter().WithTenantID(tenantID).WithAssetID(assetID)
	filter.Statuses = vulnerability.OpenStatuses()
	page := pagination.Pagination{Page: 1, PerPage: r.perPage}
	opts := vulnerability.FindingListOptions{}

	var (
		computed []shared.ID
		changed  int
		failed   error
	)
	for {
		res, err := r.findings.List(ctx, filter, opts, page)
		if err != nil {
			return computed, changed, fmt.Errorf("list findings: %w", err)
		}
		if len(res.Data) == 0 {
			break
		}
		open := make([]*vulnerability.Finding, 0, len(res.Data))
		for _, f := range res.Data {
			// Defensive: the filter already keeps closed findings out.
			if vulnerability.IsOpenStatus(f.Status()) {
				open = append(open, f)
			}
		}
		before := make(map[shared.ID]classSnapshot, len(open))
		for _, f := range open {
			before[f.ID()] = snapshotOf(f)
		}
		if err := r.classifier.EnrichAndClassifyBatch(ctx, tenantID, open, assets); err != nil {
			return computed, changed, fmt.Errorf("classify: %w", err)
		}
		if r.sla != nil {
			if err := r.sla.ApplyBatch(ctx, tenantID, open); err != nil {
				r.logger.Warn("sla recompute failed", "asset_id", assetID.String(), "error", err)
			}
		}
		for _, f := range open {
			// Rewriting an unchanged row costs a tuple in every findings index
			// for nothing: only a change is persisted.
			if snapshotOf(f) == before[f.ID()] {
				computed = append(computed, f.ID())
				continue
			}
			if err := r.findings.Update(ctx, f); err != nil {
				r.logger.Warn("persist reclassified finding failed", "finding_id", f.ID().String(), "error", err)
				if failed == nil {
					failed = fmt.Errorf("persist finding: %w", err)
				}
				continue
			}
			computed = append(computed, f.ID())
			changed++
		}
		if len(res.Data) < page.PerPage {
			break
		}
		page.Page++
	}
	return computed, changed, failed
}

// classSnapshot is what a pass can change on a finding: the priority class
// and its reason, the derived reachability, the EPSS / KEV enrichment and the
// SLA deadline and status recomputed from them.
type classSnapshot struct {
	class, reason string
	reachable     bool
	reachFrom     int
	epss          float64
	hasEPSS       bool
	kev           bool
	slaDeadline   int64 // UnixNano; 0 = none
	slaStatus     vulnerability.SLAStatus
}

func snapshotOf(f *vulnerability.Finding) classSnapshot {
	s := classSnapshot{
		reason:    f.PriorityClassReason(),
		reachable: f.IsReachable(),
		reachFrom: f.ReachableFromCount(),
		kev:       f.IsInKEV(),
		slaStatus: f.SLAStatus(),
	}
	if pc := f.PriorityClass(); pc != nil {
		s.class = string(*pc)
	}
	if e := f.EPSSScore(); e != nil {
		s.epss, s.hasEPSS = *e, true
	}
	if d := f.SLADeadline(); d != nil {
		s.slaDeadline = d.UnixNano()
	}
	return s
}
