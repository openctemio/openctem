package vulnfeed

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeStatus struct {
	st      *threatintel.SyncStatus
	updates int
}

func newFakeStatus(enabled bool, meta map[string]any) *fakeStatus {
	st := threatintel.NewSyncStatus(SourceNVD, 24)
	st.SetEnabled(enabled)
	if meta != nil {
		st.SetMetadata(meta)
	}
	return &fakeStatus{st: st}
}

func (f *fakeStatus) GetBySource(context.Context, string) (*threatintel.SyncStatus, error) {
	return f.st, nil
}
func (f *fakeStatus) GetAll(context.Context) ([]*threatintel.SyncStatus, error) { return nil, nil }
func (f *fakeStatus) GetEnabled(context.Context) ([]*threatintel.SyncStatus, error) {
	return nil, nil
}
func (f *fakeStatus) GetDueForSync(context.Context) ([]*threatintel.SyncStatus, error) {
	return nil, nil
}
func (f *fakeStatus) Update(_ context.Context, st *threatintel.SyncStatus) error {
	f.updates++
	f.st = st
	return nil
}

type fakeStore struct {
	pages   int
	cves    int
	emptied int
	ranges  int
}

func (f *fakeStore) EmptiedRanges(context.Context, []cvecorpus.CVE) (int, error) {
	return f.emptied, nil
}
func (f *fakeStore) ApplyPage(_ context.Context, cves []cvecorpus.CVE) (cvecorpus.PageResult, error) {
	f.pages++
	f.cves += len(cves)
	return cvecorpus.PageResult{Upserted: len(cves)}, nil
}
func (f *fakeStore) Counts(context.Context) (int, int, error) { return f.cves, f.ranges, nil }

type fakeCatalog struct{ curated int }

func (f *fakeCatalog) EnsureCurated(context.Context, []software.Curated) error {
	f.curated++
	return nil
}
func (f *fakeCatalog) Resolve(context.Context, shared.ID, []software.Identity) (map[software.Identity]software.ProductRef, error) {
	return nil, nil
}
func (f *fakeCatalog) EnsureVersion(context.Context, shared.ID, software.ProductRef, software.VersionKey) (shared.ID, error) {
	return shared.ID{}, nil
}
func (f *fakeCatalog) UpsertLinks(context.Context, shared.ID, []software.Link) (software.LinkResult, error) {
	return software.LinkResult{}, nil
}

// fakePager serves total CVEs in pages of size and records the queries.
type fakePager struct {
	total, size int
	queries     []PageQuery
	failAt      int
}

func (f *fakePager) FetchPage(_ context.Context, q PageQuery) (*Page, error) {
	f.queries = append(f.queries, q)
	if f.failAt > 0 && len(f.queries) == f.failAt {
		return nil, errors.New("boom")
	}
	n := f.size
	if q.StartIndex+n > f.total {
		n = f.total - q.StartIndex
	}
	if n < 0 {
		n = 0
	}
	p := &Page{TotalResults: f.total, Count: n}
	for i := 0; i < n; i++ {
		p.CVEs = append(p.CVEs, cvecorpus.CVE{ID: fmt.Sprintf("CVE-2020-%05d", q.StartIndex+i)})
	}
	return p, nil
}

// clock advances one minute per call, so budgets are deterministic.
func clock(start time.Time) func() time.Time {
	t := start
	return func() time.Time {
		t = t.Add(time.Minute)
		return t
	}
}

func newTestSyncer(p Pager, st *fakeStatus, store *fakeStore) (*Syncer, *fakeCatalog) {
	cat := &fakeCatalog{}
	s := NewSyncer(p, store, st, cat, logger.NewNop())
	s.now = clock(time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC))
	return s, cat
}

func TestSyncer_DisabledDoesNothing(t *testing.T) {
	pager := &fakePager{total: 10, size: 5}
	st := newFakeStatus(false, nil)
	s, cat := newTestSyncer(pager, st, &fakeStore{})
	res, err := s.Run(context.Background(), time.Hour)
	if err != nil || res.Ran || len(pager.queries) != 0 || cat.curated != 0 || st.updates != 0 {
		t.Fatalf("res=%+v err=%v queries=%d", res, err, len(pager.queries))
	}
}

func TestSyncer_BootstrapResumesThenIncremental(t *testing.T) {
	pager := &fakePager{total: 11, size: 2}
	st := newFakeStatus(true, nil)
	store := &fakeStore{}
	s, cat := newTestSyncer(pager, st, store)

	// A small budget stops the bootstrap part way.
	res, err := s.Run(context.Background(), 5*time.Minute)
	if err != nil || !res.Bootstrap || res.Done || cat.curated != 1 {
		t.Fatalf("first run: %+v %v", res, err)
	}
	p := readProgress(st.st.Metadata())
	if p.BootstrapDone || p.StartIndex == 0 || p.StartIndex >= 11 || p.BootstrapStarted.IsZero() {
		t.Fatalf("progress after first run: %+v", p)
	}
	firstStart := p.BootstrapStarted

	// The next run continues from there and finishes.
	res, err = s.Run(context.Background(), time.Hour)
	if err != nil || !res.Done {
		t.Fatalf("second run: %+v %v", res, err)
	}
	p = readProgress(st.st.Metadata())
	if !p.BootstrapDone || !p.BootstrapStarted.Equal(firstStart) || !p.Cursor.Equal(firstStart.Add(-cursorOverlap)) {
		t.Fatalf("progress after bootstrap: %+v", p)
	}
	if store.cves != 11 || st.st.LastSyncStatus() != threatintel.SyncStateSuccess {
		t.Fatalf("cves %d status %s", store.cves, st.st.LastSyncStatus())
	}
	for i, q := range pager.queries {
		if q.StartIndex != i*2 || !q.ModifiedGTE.IsZero() {
			t.Fatalf("query %d: %+v", i, q)
		}
	}

	// Not due again until the interval passes.
	before := len(pager.queries)
	res, _ = s.Run(context.Background(), time.Hour)
	if res.Ran || len(pager.queries) != before {
		t.Fatal("ran before it was due")
	}
}

func TestSyncer_IncrementalWindows(t *testing.T) {
	cursor := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st := newFakeStatus(true, map[string]any{"bootstrap_done": true, "cursor": cursor.Format(time.RFC3339)})
	pager := &fakePager{total: 0, size: 2}
	s, _ := newTestSyncer(pager, st, &fakeStore{})
	res, err := s.Run(context.Background(), 24*time.Hour)
	if err != nil || !res.Done {
		t.Fatalf("%+v %v", res, err)
	}
	// 2026-01-01 → 2026-10-09: three windows of at most 120 days, contiguous.
	if len(pager.queries) != 3 {
		t.Fatalf("queries %+v", pager.queries)
	}
	prev := cursor
	for _, q := range pager.queries {
		if !q.ModifiedGTE.Equal(prev) || q.ModifiedLT.Sub(q.ModifiedGTE) > MaxWindow {
			t.Fatalf("window %+v", q)
		}
		prev = q.ModifiedLT
	}
	p := readProgress(st.st.Metadata())
	if !p.Cursor.Equal(prev.Add(-cursorOverlap)) {
		t.Fatalf("cursor %v want %v", p.Cursor, prev.Add(-cursorOverlap))
	}
}

func TestSyncer_GuardRefusesMassRemoval(t *testing.T) {
	st := newFakeStatus(true, nil)
	store := &fakeStore{emptied: minEmptiedLimit + 1}
	pager := &fakePager{total: 4, size: 2}
	s, _ := newTestSyncer(pager, st, store)
	_, err := s.Run(context.Background(), time.Hour)
	if !errors.Is(err, ErrGuardRefused) {
		t.Fatalf("err %v", err)
	}
	if store.pages != 0 || st.st.LastSyncStatus() != threatintel.SyncStateFailed {
		t.Fatalf("pages %d status %s", store.pages, st.st.LastSyncStatus())
	}
}

func TestSyncer_FailureKeepsProgress(t *testing.T) {
	st := newFakeStatus(true, nil)
	pager := &fakePager{total: 10, size: 2, failAt: 3}
	s, _ := newTestSyncer(pager, st, &fakeStore{})
	if _, err := s.Run(context.Background(), time.Hour); err == nil {
		t.Fatal("no error")
	}
	p := readProgress(st.st.Metadata())
	if p.StartIndex != 4 || st.st.LastSyncStatus() != threatintel.SyncStateFailed {
		t.Fatalf("progress %+v status %s", p, st.st.LastSyncStatus())
	}
	// The next run resumes at 4.
	pager.failAt = 0
	pager.queries = nil
	if _, err := s.Run(context.Background(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if pager.queries[0].StartIndex != 4 {
		t.Fatalf("resumed at %d", pager.queries[0].StartIndex)
	}
}

// An admin turning the feed off mid-run is not overwritten.
func TestSyncer_KeepsAdminToggle(t *testing.T) {
	st := newFakeStatus(true, nil)
	pager := &fakePager{total: 6, size: 2}
	s, _ := newTestSyncer(pager, st, &fakeStore{})
	orig := s.store
	s.store = disablingStore{Store: orig, status: st}
	_, _ = s.Run(context.Background(), time.Hour)
	if st.st.IsEnabled() {
		t.Fatal("the run re-enabled a feed an admin disabled")
	}
}

type disablingStore struct {
	cvecorpus.Store
	status *fakeStatus
}

func (d disablingStore) ApplyPage(ctx context.Context, cves []cvecorpus.CVE) (cvecorpus.PageResult, error) {
	d.status.st.SetEnabled(false)
	return d.Store.ApplyPage(ctx, cves)
}
