package programfeed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Bundles written and signed by the collector (openctemio/programfeed).
const collector = "../../../pkg/programfeed/testdata/collector"

type memCatalog struct {
	state   bp.FeedState
	applied []bp.FeedApply
	stale   []bp.ProgramRef
}

func (m *memCatalog) FeedState(context.Context) (bp.FeedState, error) { return m.state, nil }
func (m *memCatalog) Apply(_ context.Context, a bp.FeedApply) ([]bp.CatalogChange, error) {
	m.state = a.State
	m.applied = append(m.applied, a)
	return []bp.CatalogChange{{Kind: bp.ChangeChanged}}, nil
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

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(collector, name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestImporter(t *testing.T) {
	ctx := context.Background()
	root := readFixture(t, "root-keyid.txt")
	at, err := time.Parse(time.RFC3339, readFixture(t, "created-at.txt"))
	if err != nil {
		t.Fatal(err)
	}
	cat := &memCatalog{stale: []bp.ProgramRef{{}}}
	subs := &memSubs{}
	imp := NewImporter(DirSource(filepath.Join(collector, "seq2")), cat, subs, root, nil)
	imp.now = func() time.Time { return at.Add(time.Minute) }

	// First import: the snapshot; subscribed programs reconciled.
	res, err := imp.Import(ctx)
	if err != nil {
		t.Fatalf("import seq2: %v", err)
	}
	if res.Sequence != 2 || res.Delta || res.Programs != 2 || !cat.applied[0].Snapshot || cat.state.KeySetVersion != 1 {
		t.Fatalf("seq2: %+v %+v", res, cat.applied)
	}
	if subs.applied != 1 || res.Subscribers["needs_acceptance"] != 1 {
		t.Fatalf("reconcile: %d %+v", subs.applied, res.Subscribers)
	}
	// The same bundle again: nothing to do.
	if res, err := imp.Import(ctx); err != nil || len(cat.applied) != 1 || res.Sequence != 2 {
		t.Fatalf("re-import: %+v %v", res, err)
	}
	// Next: the delta from 2.
	imp.source = DirSource(filepath.Join(collector, "seq3"))
	res, err = imp.Import(ctx)
	if err != nil {
		t.Fatalf("import seq3: %v", err)
	}
	if !res.Delta || cat.applied[1].Snapshot || cat.state.AppliedSequence != 3 {
		t.Fatalf("seq3: %+v %+v", res, cat.applied[1])
	}

	// A tampered bundle is refused and nothing is applied.
	dir := t.TempDir()
	src := filepath.Join(collector, "seq3")
	entries, _ := os.ReadDir(src)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(src, e.Name()))
		if e.Name() == "snapshot-programs.jsonl.gz" {
			b[len(b)-1] ^= 0xff
		}
		_ = os.WriteFile(filepath.Join(dir, e.Name()), b, 0o600)
	}
	cat.state = bp.FeedState{}
	imp.source = DirSource(dir)
	if _, err := imp.Import(ctx); err == nil || len(cat.applied) != 2 {
		t.Fatalf("tampered bundle: %v (applies %d)", err, len(cat.applied))
	}

	// Without a pinned root nothing is imported.
	if _, err := NewImporter(DirSource(src), cat, subs, "", nil).Import(ctx); err == nil {
		t.Fatal("imported without a pinned root")
	}
	if _, _, err := DirSource("").Fetch(ctx); err == nil {
		t.Fatal("empty dir source accepted")
	}
}
