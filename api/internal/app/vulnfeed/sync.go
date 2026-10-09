package vulnfeed

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SourceNVD is the threat_intel_sync_status row of the feed.
const SourceNVD = "nvd"

// Guard: a sync may not empty more stored ranges than this share of the
// corpus (or this many, whichever is larger) for CVEs that were not
// rejected. A feed that suddenly drops ranges is treated as bad input.
const (
	maxEmptiedShare = 0.02
	minEmptiedLimit = 500
	cursorOverlap   = 10 * time.Minute
)

// ErrGuardRefused means a page would have removed too many ranges.
var ErrGuardRefused = errors.New("nvd sync refused: the feed would remove too many affected ranges")

// Pager fetches pages; *Client implements it.
type Pager interface {
	FetchPage(ctx context.Context, q PageQuery) (*Page, error)
}

// Syncer runs the NVD feed: a resumable bootstrap through the whole API,
// then daily windows of modified CVEs.
type Syncer struct {
	pager   Pager
	store   cvecorpus.Store
	status  threatintel.SyncStatusRepository
	catalog software.Repository
	logger  *logger.Logger
	now     func() time.Time
}

// NewSyncer creates a Syncer.
func NewSyncer(pager Pager, store cvecorpus.Store, status threatintel.SyncStatusRepository, catalog software.Repository, log *logger.Logger) *Syncer {
	return &Syncer{pager: pager, store: store, status: status, catalog: catalog, logger: log, now: time.Now}
}

// Result of one run.
type Result struct {
	Ran       bool
	Pages     int
	CVEs      int
	Ranges    int
	Bootstrap bool
	Done      bool // bootstrap finished or the incremental window reached now
}

// progress is the feed's state in the status row's metadata.
type progress struct {
	BootstrapDone    bool
	StartIndex       int
	BootstrapStarted time.Time
	Cursor           time.Time
}

func readProgress(m map[string]any) progress {
	var p progress
	p.BootstrapDone, _ = m["bootstrap_done"].(bool)
	if v, ok := m["start_index"].(float64); ok && v >= 0 {
		p.StartIndex = int(v)
	}
	if v, ok := m["start_index"].(int); ok && v >= 0 {
		p.StartIndex = v
	}
	if v, ok := m["bootstrap_started"].(string); ok {
		p.BootstrapStarted, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := m["cursor"].(string); ok {
		p.Cursor, _ = time.Parse(time.RFC3339, v)
	}
	return p
}

// apply writes the progress into a copy of the row's metadata.
func (p progress) apply(meta map[string]any) map[string]any {
	meta["bootstrap_done"] = p.BootstrapDone
	meta["start_index"] = p.StartIndex
	delete(meta, "bootstrap_started")
	delete(meta, "cursor")
	if !p.BootstrapStarted.IsZero() {
		meta["bootstrap_started"] = p.BootstrapStarted.UTC().Format(time.RFC3339)
	}
	if !p.Cursor.IsZero() {
		meta["cursor"] = p.Cursor.UTC().Format(time.RFC3339)
	}
	return meta
}

// run is the state of one Run.
type run struct {
	p        progress
	res      Result
	started  time.Time
	deadline time.Time
	limit    int
	emptied  int
}

// Run does as much work as fits in budget. It does nothing while the feed
// is disabled, and between incremental syncs until the next one is due.
func (s *Syncer) Run(ctx context.Context, budget time.Duration) (Result, error) {
	status, err := s.status.GetBySource(ctx, SourceNVD)
	if err != nil {
		return Result{}, fmt.Errorf("nvd sync status: %w", err)
	}
	if !status.IsEnabled() {
		return Result{}, nil
	}
	r := &run{p: readProgress(status.Metadata())}
	if r.p.BootstrapDone && !status.IsDueForSync() {
		return Result{}, nil
	}
	r.res.Ran = true
	r.res.Bootstrap = !r.p.BootstrapDone
	r.started = s.now()
	r.deadline = r.started.Add(budget)

	if err := s.catalog.EnsureCurated(ctx, software.CuratedProducts()); err != nil {
		return r.res, s.fail(ctx, fmt.Errorf("curated products: %w", err))
	}
	_, stored, err := s.store.Counts(ctx)
	if err != nil {
		return r.res, s.fail(ctx, err)
	}
	r.limit = max(int(float64(stored)*maxEmptiedShare), minEmptiedLimit)
	if err := s.save(ctx, r.p, func(st *threatintel.SyncStatus) { st.MarkSyncStarted() }); err != nil {
		return r.res, err
	}
	if r.p.BootstrapDone {
		err = s.incremental(ctx, r)
	} else {
		err = s.bootstrap(ctx, r)
	}
	if err != nil {
		return r.res, err
	}
	return r.res, s.finish(ctx, r)
}

// bootstrap pages through the whole API from the saved start index.
func (s *Syncer) bootstrap(ctx context.Context, r *run) error {
	if r.p.StartIndex == 0 || r.p.BootstrapStarted.IsZero() {
		r.p.BootstrapStarted = r.started
	}
	for s.now().Before(r.deadline) {
		page, err := s.pager.FetchPage(ctx, PageQuery{StartIndex: r.p.StartIndex})
		if err != nil {
			return s.fail(ctx, err)
		}
		if err := s.apply(ctx, r, page); err != nil {
			return s.fail(ctx, err)
		}
		r.p.StartIndex += page.Count
		if page.Count == 0 || r.p.StartIndex >= page.TotalResults {
			r.p.BootstrapDone = true
			r.p.Cursor = r.p.BootstrapStarted.Add(-cursorOverlap)
			r.p.StartIndex = 0
			r.res.Done = true
			return nil
		}
		if err := s.save(ctx, r.p, nil); err != nil {
			return err
		}
	}
	return nil
}

// incremental reads the CVEs modified since the cursor, window by window.
func (s *Syncer) incremental(ctx context.Context, r *run) error {
	from := r.p.Cursor
	if from.IsZero() {
		from = r.started.Add(-MaxWindow)
	}
	for from.Before(r.started) && s.now().Before(r.deadline) {
		to := from.Add(MaxWindow)
		if to.After(r.started) {
			to = r.started
		}
		if err := s.window(ctx, from, to, func(p *Page) error { return s.apply(ctx, r, p) }); err != nil {
			return s.fail(ctx, err)
		}
		from = to
		r.p.Cursor = to.Add(-cursorOverlap)
		r.res.Done = !from.Before(r.started)
		if err := s.save(ctx, r.p, nil); err != nil {
			return err
		}
	}
	return nil
}

// apply writes one page behind the removal guard.
func (s *Syncer) apply(ctx context.Context, r *run, page *Page) error {
	e, err := s.store.EmptiedRanges(ctx, page.CVEs)
	if err != nil {
		return err
	}
	if r.emptied+e > r.limit {
		return fmt.Errorf("%w (%d ranges, limit %d)", ErrGuardRefused, r.emptied+e, r.limit)
	}
	pr, err := s.store.ApplyPage(ctx, page.CVEs)
	if err != nil {
		return err
	}
	r.emptied += e
	r.res.Pages++
	r.res.CVEs += pr.Upserted
	r.res.Ranges += pr.RangesWritten
	for _, c := range page.CVEs {
		if c.TooManyRanges {
			s.logger.Warn("nvd: CVE has more statements than the corpus keeps; old ranges kept", "cve", c.ID)
		}
	}
	return nil
}

// finish records the corpus size and, when the run completed, success.
func (s *Syncer) finish(ctx context.Context, r *run) error {
	records, ranges, err := s.store.Counts(ctx)
	if err != nil {
		return s.fail(ctx, err)
	}
	if err := s.save(ctx, r.p, func(st *threatintel.SyncStatus) {
		meta := st.Metadata()
		meta["records"], meta["ranges"] = records, ranges
		st.SetMetadata(meta)
		if r.res.Done {
			st.MarkSyncSuccess(r.res.CVEs, int(s.now().Sub(r.started).Milliseconds()))
		}
	}); err != nil {
		return err
	}
	s.logger.Info("nvd sync", "bootstrap", r.res.Bootstrap, "done", r.res.Done, "pages", r.res.Pages,
		"cves", r.res.CVEs, "ranges_written", r.res.Ranges, "corpus_records", records, "corpus_ranges", ranges)
	return nil
}

func (s *Syncer) window(ctx context.Context, from, to time.Time, apply func(*Page) error) error {
	for start := 0; ; {
		page, err := s.pager.FetchPage(ctx, PageQuery{StartIndex: start, ModifiedGTE: from, ModifiedLT: to})
		if err != nil {
			return err
		}
		if err := apply(page); err != nil {
			return err
		}
		start += page.Count
		if page.Count == 0 || start >= page.TotalResults {
			return nil
		}
	}
}

// save re-reads the status row (an admin may have changed it meanwhile),
// writes the progress and applies mut.
func (s *Syncer) save(ctx context.Context, p progress, mut func(*threatintel.SyncStatus)) error {
	st, err := s.status.GetBySource(ctx, SourceNVD)
	if err != nil {
		return fmt.Errorf("nvd sync status: %w", err)
	}
	st.SetMetadata(p.apply(st.Metadata()))
	if mut != nil {
		mut(st)
	}
	if err := s.status.Update(ctx, st); err != nil {
		return fmt.Errorf("nvd sync status: %w", err)
	}
	return nil
}

// fail records the failure; the progress saved so far is kept, so the next
// run resumes where this one stopped.
func (s *Syncer) fail(ctx context.Context, cause error) error {
	st, err := s.status.GetBySource(ctx, SourceNVD)
	if err == nil {
		st.MarkSyncFailed(cause.Error())
		err = s.status.Update(ctx, st)
	}
	if err != nil {
		s.logger.Warn("nvd sync status not updated", "error", err)
	}
	return cause
}
