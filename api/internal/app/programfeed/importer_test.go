package programfeed

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	feed "github.com/openctemio/openctem/api/pkg/programfeed"
	"github.com/openctemio/openctem/api/pkg/programfeed/programfeedtest"
)

var now = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

type memCatalog struct {
	state    bp.FeedState
	programs []bp.PublicProgram
	applies  int
	stale    []bp.ProgramRef
}

func (m *memCatalog) FeedState(context.Context) (bp.FeedState, error) { return m.state, nil }
func (m *memCatalog) ApplySnapshot(_ context.Context, st bp.FeedState, ps []bp.PublicProgram) ([]bp.CatalogChange, error) {
	m.state, m.programs = st, ps
	m.applies++
	return []bp.CatalogChange{{FeedID: ps[0].FeedID, Kind: bp.ChangeChanged}}, nil
}
func (m *memCatalog) ListPublic(context.Context, string, int, int) ([]bp.PublicProgram, int, error) {
	return nil, 0, nil
}
func (m *memCatalog) GetPublic(context.Context, shared.ID) (*bp.PublicProgram, error) {
	return nil, bp.ErrNotFound
}
func (m *memCatalog) StaleSubscriptions(context.Context, int) ([]bp.ProgramRef, error) {
	out := m.stale
	m.stale = nil
	return out, nil
}

type memSubs struct{ applied int }

func (s *memSubs) ApplyFeedChange(context.Context, bp.ProgramRef) (string, error) {
	s.applied++
	return "needs_acceptance", nil
}

func TestImporter(t *testing.T) {
	ctx := context.Background()
	b := programfeedtest.New(t, now)
	recs := []map[string]any{programfeedtest.Record("acme-bounty", "acme", []string{"*.acme.example"}, nil, now)}
	dir := b.Write(t, 3, recs)
	cat := &memCatalog{stale: []bp.ProgramRef{{}}}
	subs := &memSubs{}
	imp := NewImporter(DirSource(dir), cat, subs, b.RootKeyID(), nil)
	imp.now = func() time.Time { return now }

	res, err := imp.Import(ctx)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.Sequence != 3 || res.Programs != 1 || cat.state.AppliedSequence != 3 || cat.state.KeySetVersion != 1 {
		t.Fatalf("result %+v state %+v", res, cat.state)
	}
	if subs.applied != 1 || res.Subscribers["needs_acceptance"] != 1 {
		t.Fatalf("subscriptions reconciled: %d %+v", subs.applied, res.Subscribers)
	}
	// The same bundle again: nothing to do.
	if res, err := imp.Import(ctx); err != nil || cat.applies != 1 || res.Sequence != 3 {
		t.Fatalf("re-import: %+v %v (applies %d)", res, err, cat.applies)
	}

	// A tampered bundle is refused and the catalog is untouched.
	dir2 := b.Write(t, 4, recs)
	raw, _ := os.ReadFile(filepath.Join(dir2, feed.ProgramsFile))
	raw[len(raw)-1] ^= 0xff
	_ = os.WriteFile(filepath.Join(dir2, feed.ProgramsFile), raw, 0o600)
	imp.source = DirSource(dir2)
	if _, err := imp.Import(ctx); err == nil || cat.applies != 1 {
		t.Fatalf("tampered bundle: %v (applies %d)", err, cat.applies)
	}

	// Without a pinned root nothing is imported.
	if _, err := NewImporter(DirSource(dir), cat, subs, "", nil).Import(ctx); err == nil {
		t.Fatal("imported without a pinned root")
	}
	if _, _, err := DirSource("").Fetch(ctx); err == nil {
		t.Fatal("empty dir source accepted")
	}
}
