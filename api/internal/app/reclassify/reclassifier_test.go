package reclassify

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/scoring"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// --- fakes ---

type fakeFindingRepo struct {
	vulnerability.FindingRepository // embed; only List/Update used
	findings                        []*vulnerability.Finding
	updated                         []shared.ID
	lastFilter                      vulnerability.FindingFilter
	updateErr                       error
}

func (r *fakeFindingRepo) List(_ context.Context, f vulnerability.FindingFilter, _ vulnerability.FindingListOptions, p pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	r.lastFilter = f
	if p.Page > 1 {
		return pagination.Result[*vulnerability.Finding]{}, nil
	}
	return pagination.Result[*vulnerability.Finding]{Data: r.findings}, nil
}

func (r *fakeFindingRepo) Update(_ context.Context, f *vulnerability.Finding) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	r.updated = append(r.updated, f.ID())
	return nil
}

type fakeAssetRepo struct {
	asset.Repository
	a   *asset.Asset
	err error
}

func (r *fakeAssetRepo) GetByID(_ context.Context, _, _ shared.ID) (*asset.Asset, error) {
	return r.a, r.err
}

// fakeClassifier classifies every finding it is given as P1 with a fixed
// reason, so a finding stored with another class changes and one already P1
// does not.
type fakeClassifier struct{ seen []shared.ID }

func (c *fakeClassifier) EnrichAndClassifyBatch(_ context.Context, _ shared.ID, fs []*vulnerability.Finding, _ map[shared.ID]*asset.Asset) error {
	for _, f := range fs {
		c.seen = append(c.seen, f.ID())
		f.SetPriorityClassification(vulnerability.PriorityP1, "fake")
	}
	return nil
}

type fakeSLA struct{ applied []shared.ID }

func (s *fakeSLA) ApplyBatch(_ context.Context, _ shared.ID, findings []*vulnerability.Finding) error {
	for _, f := range findings {
		s.applied = append(s.applied, f.ID())
	}
	return nil
}

type fakeQueue struct {
	scoring.PriorityQueue
	items    []scoring.QueueItem
	stamped  map[shared.ID]int64
	requeued []shared.ID
	impacts  []scoring.ChangeSummary
}

func (q *fakeQueue) Claim(_ context.Context, _, _ int) ([]scoring.QueueItem, error) {
	it := q.items
	q.items = nil
	return it, nil
}

func (q *fakeQueue) StampVersion(_ context.Context, _ shared.ID, ids []shared.ID, v int64) error {
	if q.stamped == nil {
		q.stamped = map[shared.ID]int64{}
	}
	for _, id := range ids {
		q.stamped[id] = v
	}
	return nil
}

func (q *fakeQueue) EnqueueAssets(_ context.Context, _ shared.ID, ids []shared.ID, _ string) error {
	q.requeued = append(q.requeued, ids...)
	return nil
}

func (q *fakeQueue) Stats(context.Context) (scoring.QueueStats, error) {
	return scoring.QueueStats{}, nil
}

func (q *fakeQueue) EnqueueReconcile(context.Context, time.Duration) (int64, error) { return 0, nil }

func (q *fakeQueue) RecordImpact(_ context.Context, tid shared.ID, change int64, im scoring.ChangeImpact) error {
	q.impacts = append(q.impacts, scoring.ChangeSummary{TenantID: tid, ChangeID: change, ChangeImpact: im})
	return nil
}

// ClaimDrainedSummaries hands back every recorded impact once.
func (q *fakeQueue) ClaimDrainedSummaries(context.Context, int) ([]scoring.ChangeSummary, error) {
	out := q.impacts
	q.impacts = nil
	return out, nil
}

type fakeVersions struct{ v int64 }

func (f fakeVersions) CurrentVersion(context.Context, shared.ID, scoring.Kind) (int64, error) {
	return f.v, nil
}
func (fakeVersions) RegisterModels(context.Context) error { return nil }

func newFinding(t *testing.T, assetID shared.ID) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(shared.NewID(), assetID, vulnerability.FindingSourceManual, "tool", vulnerability.SeverityHigh, "f")
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	return f
}

func newAsset(t *testing.T) *asset.Asset {
	t.Helper()
	a, err := asset.NewAsset("example.com", asset.AssetTypeDomain, asset.CriticalityHigh)
	if err != nil {
		t.Fatalf("new asset: %v", err)
	}
	return a
}

func TestReclassify_ListsOnlyOpenFindings(t *testing.T) {
	assetID := shared.NewID()
	repo := &fakeFindingRepo{}
	r := NewReclassifier(repo, &fakeAssetRepo{a: newAsset(t)}, &fakeClassifier{}, logger.NewNop())
	if _, _, err := r.reclassifyAsset(context.Background(), shared.NewID(), assetID); err != nil {
		t.Fatal(err)
	}
	if len(repo.lastFilter.Statuses) == 0 {
		t.Fatal("the list must be limited to open statuses")
	}
	for _, st := range repo.lastFilter.Statuses {
		if !vulnerability.IsOpenStatus(st) {
			t.Fatalf("closed status %q in the filter", st)
		}
	}
}

// A closed finding that reaches the pass anyway is left exactly as it was:
// not classified, not given a new deadline, not written, not stamped.
func TestReclassify_ClosedFindingStaysFrozen(t *testing.T) {
	assetID := shared.NewID()
	open := newFinding(t, assetID)
	closed := newFinding(t, assetID)
	if err := closed.TransitionStatus(vulnerability.FindingStatusFalsePositive, "fp", nil); err != nil {
		t.Fatalf("close: %v", err)
	}
	closed.SetPriorityClassification(vulnerability.PriorityP3, "at close")

	repo := &fakeFindingRepo{findings: []*vulnerability.Finding{open, closed}}
	cls := &fakeClassifier{}
	sla := &fakeSLA{}
	q := &fakeQueue{}
	r := NewReclassifier(repo, &fakeAssetRepo{a: newAsset(t)}, cls, logger.NewNop())
	r.SetSLARecomputer(sla)
	r.SetQueue(q, fakeVersions{v: 7})

	if _, err := r.ReclassifyAssets(context.Background(), shared.NewID(), []shared.ID{assetID}); err != nil {
		t.Fatal(err)
	}
	for _, id := range append(append(cls.seen, sla.applied...), repo.updated...) {
		if id == closed.ID() {
			t.Fatal("the closed finding was recomputed")
		}
	}
	if _, ok := q.stamped[closed.ID()]; ok {
		t.Fatal("the closed finding was stamped")
	}
	if pc := closed.PriorityClass(); pc == nil || *pc != vulnerability.PriorityP3 {
		t.Fatalf("closed finding class = %v, want P3", pc)
	}
	if q.stamped[open.ID()] != 7 {
		t.Fatalf("open finding stamp = %d, want 7", q.stamped[open.ID()])
	}
}

func TestReclassify_RecomputesSLAAndPersistsChanges(t *testing.T) {
	assetID := shared.NewID()
	f1, f2 := newFinding(t, assetID), newFinding(t, assetID)
	repo := &fakeFindingRepo{findings: []*vulnerability.Finding{f1, f2}}
	sla := &fakeSLA{}
	r := NewReclassifier(repo, &fakeAssetRepo{a: newAsset(t)}, &fakeClassifier{}, logger.NewNop())
	r.SetSLARecomputer(sla)

	ids, im, err := r.reclassifyAsset(context.Background(), shared.NewID(), assetID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || im.Checked != 2 || len(sla.applied) != 2 || len(repo.updated) != 2 {
		t.Fatalf("ids=%d checked=%d sla=%d updated=%d, want 2 each", len(ids), im.Checked, len(sla.applied), len(repo.updated))
	}
	// A first classification is not a priority change.
	if im.Changed != 0 {
		t.Fatalf("changed = %d, want 0 for first classifications", im.Changed)
	}
}

// A pass that re-confirms the stored values writes nothing but still
// stamps the version (the finding is no longer stale).
func TestReclassify_UnchangedIsNotRewrittenButStamped(t *testing.T) {
	assetID := shared.NewID()
	same := newFinding(t, assetID)
	same.SetPriorityClassification(vulnerability.PriorityP1, "fake")
	repo := &fakeFindingRepo{findings: []*vulnerability.Finding{same}}
	q := &fakeQueue{}
	r := NewReclassifier(repo, &fakeAssetRepo{a: newAsset(t)}, &fakeClassifier{}, logger.NewNop())
	r.SetQueue(q, fakeVersions{v: 3})

	im, err := r.ReclassifyAssets(context.Background(), shared.NewID(), []shared.ID{assetID})
	if err != nil {
		t.Fatal(err)
	}
	if im.Checked != 1 || im.Changed != 0 || len(repo.updated) != 0 {
		t.Fatalf("checked=%d changed=%d updated=%d", im.Checked, im.Changed, len(repo.updated))
	}
	if q.stamped[same.ID()] != 3 {
		t.Fatalf("stamp = %d, want 3", q.stamped[same.ID()])
	}
}

// A failed write is not stamped and the tenant's assets go back in the
// queue.
func TestProcessQueue_FailedPassIsRequeuedAndNotStamped(t *testing.T) {
	assetID := shared.NewID()
	tid := shared.NewID()
	f := newFinding(t, assetID)
	repo := &fakeFindingRepo{findings: []*vulnerability.Finding{f}, updateErr: errors.New("db down")}
	q := &fakeQueue{items: []scoring.QueueItem{{TenantID: tid, AssetID: assetID, Reason: scoring.ReasonNewFinding}}}
	r := NewReclassifier(repo, &fakeAssetRepo{a: newAsset(t)}, &fakeClassifier{}, logger.NewNop())
	r.SetQueue(q, fakeVersions{v: 5})

	res, err := r.ProcessQueue(context.Background(), 10, 5)
	if err == nil {
		t.Fatal("want the persist error")
	}
	if res.Claimed != 1 {
		t.Fatalf("claimed = %d", res.Claimed)
	}
	if len(q.requeued) != 1 || q.requeued[0] != assetID {
		t.Fatalf("requeued = %v", q.requeued)
	}
	if _, ok := q.stamped[f.ID()]; ok {
		t.Fatal("a finding whose write failed was stamped")
	}
}

func TestReclassify_MissingAssetIsASoftMiss(t *testing.T) {
	r := NewReclassifier(&fakeFindingRepo{}, &fakeAssetRepo{err: shared.ErrNotFound}, &fakeClassifier{}, logger.NewNop())
	ids, im, err := r.reclassifyAsset(context.Background(), shared.NewID(), shared.NewID())
	if err != nil || im.Checked != 0 || len(ids) != 0 {
		t.Fatalf("ids=%v im=%+v err=%v", ids, im, err)
	}
}

type captureSummaries struct{ got []scoring.ChangeSummary }

func (c *captureSummaries) PublishScoringSummary(_ context.Context, s scoring.ChangeSummary) error {
	c.got = append(c.got, s)
	return nil
}

// A pass queued by a scoring change records its counts on the change and
// sends one summary; a pass queued by anything else records nothing.
func TestProcessQueue_ScoringChangeSendsOneSummary(t *testing.T) {
	tid := shared.NewID()
	a1, a2, a3 := shared.NewID(), shared.NewID(), shared.NewID()
	f1, f2 := newFinding(t, a1), newFinding(t, a2)
	f1.SetPriorityClassification(vulnerability.PriorityP3, "before")
	f2.SetPriorityClassification(vulnerability.PriorityP3, "before")
	change := int64(42)
	q := &fakeQueue{items: []scoring.QueueItem{
		{TenantID: tid, AssetID: a1, Reason: scoring.ReasonScoringChange, ScoringChangeID: &change},
		{TenantID: tid, AssetID: a2, Reason: scoring.ReasonScoringChange, ScoringChangeID: &change},
		{TenantID: tid, AssetID: a3, Reason: scoring.ReasonNewFinding},
	}}
	repo := &perAssetRepo{byAsset: map[shared.ID][]*vulnerability.Finding{a1: {f1}, a2: {f2}}}
	sum := &captureSummaries{}
	r := NewReclassifier(repo, &fakeAssetRepo{a: newAsset(t)}, &fakeClassifier{}, logger.NewNop())
	r.SetQueue(q, fakeVersions{v: 9})
	r.SetSummaryPublisher(sum)

	if _, err := r.ProcessQueue(context.Background(), 10, 10); err != nil {
		t.Fatal(err)
	}
	if len(sum.got) != 1 {
		t.Fatalf("summaries = %d, want exactly 1", len(sum.got))
	}
	got := sum.got[0]
	if got.ChangeID != change || got.TenantID != tid || got.Changed != 2 || got.Raised != 2 || got.RaisedToP0 != 0 {
		t.Fatalf("summary = %+v, want 2 raised for change 42", got)
	}
}

// perAssetRepo serves each asset its own findings.
type perAssetRepo struct {
	fakeFindingRepo
	byAsset map[shared.ID][]*vulnerability.Finding
}

func (r *perAssetRepo) List(_ context.Context, f vulnerability.FindingFilter, _ vulnerability.FindingListOptions, p pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	if p.Page > 1 || f.AssetID == nil {
		return pagination.Result[*vulnerability.Finding]{}, nil
	}
	return pagination.Result[*vulnerability.Finding]{Data: r.byAsset[*f.AssetID]}, nil
}
