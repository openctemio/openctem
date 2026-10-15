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

	"github.com/openctemio/openctem/api/internal/app/finding"
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

// PriorityWriter persists what a pass computed, only on findings that are
// still open and only the columns the pass owns (no lost update of a
// concurrent status or assignee change).
type PriorityWriter interface {
	SavePriorities(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) (int, error)
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
	summaries  SummaryPublisher
	writer     PriorityWriter
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

// SummaryPublisher sends the one notification of a scoring change.
type SummaryPublisher interface {
	PublishScoringSummary(ctx context.Context, s scoring.ChangeSummary) error
}

// SetSummaryPublisher wires the scoring change summary notification.
func (r *Reclassifier) SetSummaryPublisher(p SummaryPublisher) {
	r.summaries = p
}

// SetQueue wires the durable queue and the version source.
func (r *Reclassifier) SetQueue(q scoring.PriorityQueue, v scoring.VersionRepository) {
	r.queue = q
	r.versions = v
}

// SetWriter wires the narrow priority writer. Without one the pass falls
// back to the finding repository's full update.
func (r *Reclassifier) SetWriter(w PriorityWriter) {
	r.writer = w
}

// save persists one changed finding.
func (r *Reclassifier) save(ctx context.Context, tenantID shared.ID, f *vulnerability.Finding) error {
	if r.writer != nil {
		_, err := r.writer.SavePriorities(ctx, tenantID, []*vulnerability.Finding{f})
		return err
	}
	return r.findings.Update(ctx, f)
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

	// A pass is grouped by tenant and by the scoring change that queued the
	// asset: a change's findings are recomputed without per-finding events
	// and its counts go to the change's summary.
	type group struct {
		tenant shared.ID
		change int64 // 0 = not a scoring change
		assets []shared.ID
	}
	idx := make(map[[2]string]int)
	var groups []group
	for _, it := range items {
		var change int64
		if it.ScoringChangeID != nil {
			change = *it.ScoringChangeID
		}
		k := [2]string{it.TenantID.String(), fmt.Sprint(change)}
		i, ok := idx[k]
		if !ok {
			i = len(groups)
			idx[k] = i
			groups = append(groups, group{tenant: it.TenantID, change: change})
		}
		groups[i].assets = append(groups[i].assets, it.AssetID)
	}

	var errs []error
	for _, g := range groups {
		gctx := ctx
		if g.change > 0 {
			gctx = finding.WithCoalescedChangeEvents(ctx)
		}
		impact, err := r.ReclassifyAssets(gctx, g.tenant, g.assets)
		res.Checked += impact.Checked
		res.Changed += impact.Changed
		if g.change > 0 && impact.Checked > 0 {
			if ierr := r.queue.RecordImpact(ctx, g.tenant, g.change, impact); ierr != nil {
				errs = append(errs, fmt.Errorf("tenant %s: %w", g.tenant, ierr))
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", g.tenant, err))
			requeueCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			if qerr := r.queue.EnqueueAssets(requeueCtx, g.tenant, g.assets, scoring.ReasonFindingChange); qerr != nil {
				errs = append(errs, fmt.Errorf("tenant %s requeue: %w", g.tenant, qerr))
			}
			cancel()
		}
	}
	if err := r.publishDrainedSummaries(ctx); err != nil {
		errs = append(errs, err)
	}
	return res, errors.Join(errs...)
}

// publishDrainedSummaries sends one notification per scoring change whose
// recompute has drained for a tenant.
func (r *Reclassifier) publishDrainedSummaries(ctx context.Context) error {
	summaries, err := r.queue.ClaimDrainedSummaries(ctx, 50)
	if err != nil {
		return err
	}
	for _, s := range summaries {
		if r.summaries == nil {
			continue
		}
		if err := r.summaries.PublishScoringSummary(ctx, s); err != nil {
			r.logger.Warn("scoring change summary not sent", "tenant_id", s.TenantID.String(),
				"scoring_change_id", s.ChangeID, "error", err)
		}
	}
	return nil
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
// with). Returns what the pass did to the findings.
func (r *Reclassifier) ReclassifyAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (scoring.ChangeImpact, error) {
	var impact scoring.ChangeImpact
	var version int64
	if r.versions != nil {
		v, err := r.versions.CurrentVersion(ctx, tenantID, scoring.KindFindingPriority)
		if err != nil {
			return impact, err
		}
		version = v
	}
	var firstErr error
	for _, assetID := range assetIDs {
		if ctx.Err() != nil {
			return impact, ctx.Err()
		}
		ids, im, err := r.reclassifyAsset(ctx, tenantID, assetID)
		impact.Add(im)
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
	return impact, firstErr
}

// reclassifyAsset recomputes the open findings of one asset. It returns the
// ids of the findings it computed (persisted or confirmed unchanged) and what
// changed.
func (r *Reclassifier) reclassifyAsset(ctx context.Context, tenantID, assetID shared.ID) ([]shared.ID, scoring.ChangeImpact, error) {
	var impact scoring.ChangeImpact
	a, err := r.assets.GetByID(ctx, tenantID, assetID)
	if err != nil {
		// Asset gone: its findings are cleaned by lifecycle jobs.
		if errors.Is(err, shared.ErrNotFound) {
			return nil, impact, nil
		}
		return nil, impact, fmt.Errorf("load asset: %w", err)
	}
	assets := map[shared.ID]*asset.Asset{a.ID(): a}

	filter := vulnerability.NewFindingFilter().WithTenantID(tenantID).WithAssetID(assetID)
	filter.Statuses = vulnerability.OpenStatuses()
	page := pagination.Pagination{Page: 1, PerPage: r.perPage}
	opts := vulnerability.FindingListOptions{}

	var (
		computed []shared.ID
		failed   error
	)
	for {
		res, err := r.findings.List(ctx, filter, opts, page)
		if err != nil {
			return computed, impact, fmt.Errorf("list findings: %w", err)
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
			return computed, impact, fmt.Errorf("classify: %w", err)
		}
		if r.sla != nil {
			if err := r.sla.ApplyBatch(ctx, tenantID, open); err != nil {
				r.logger.Warn("sla recompute failed", "asset_id", assetID.String(), "error", err)
			}
		}
		for _, f := range open {
			// Rewriting an unchanged row costs a tuple in every findings index
			// for nothing: only a change is persisted.
			after := snapshotOf(f)
			if after == before[f.ID()] {
				computed = append(computed, f.ID())
				continue
			}
			if err := r.save(ctx, tenantID, f); err != nil {
				r.logger.Warn("persist reclassified finding failed", "finding_id", f.ID().String(), "error", err)
				if failed == nil {
					failed = fmt.Errorf("persist finding: %w", err)
				}
				continue
			}
			computed = append(computed, f.ID())
			tallyChange(&impact, before[f.ID()], after)
		}
		if len(res.Data) < page.PerPage {
			break
		}
		page.Page++
	}
	impact.Checked = len(computed)
	return computed, impact, failed
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

// tallyChange counts one persisted change: a class move (a lower class string
// is a higher priority: P0 < P3) and a deadline that moved earlier.
func tallyChange(im *scoring.ChangeImpact, before, after classSnapshot) {
	if before.class != after.class && before.class != "" {
		im.Changed++
		if after.class < before.class {
			im.Raised++
			if after.class == string(vulnerability.PriorityP0) {
				im.RaisedToP0++
			}
		} else {
			im.Lowered++
		}
	}
	if before.slaDeadline != 0 && after.slaDeadline != 0 && after.slaDeadline < before.slaDeadline {
		im.DeadlinesTightened++
	}
}
