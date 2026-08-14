package ctemid

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/ctemid"
	"github.com/openctemio/api/pkg/logger"
)

func testLogger() *logger.Logger { return logger.NewNop() }

// fakeRepo mimics the postgres ON CONFLICT(ctem_id) upsert: keyed by ctem_id, so
// re-upserting the same feed leaves the row count unchanged.
type fakeRepo struct {
	byCTEMID map[string]*ctemid.CTEMID
}

func newFakeRepo() *fakeRepo { return &fakeRepo{byCTEMID: make(map[string]*ctemid.CTEMID)} }

func (r *fakeRepo) UpsertBatch(_ context.Context, entries []*ctemid.CTEMID) error {
	for _, e := range entries {
		r.byCTEMID[e.CTEMID()] = e
	}
	return nil
}
func (r *fakeRepo) List(_ context.Context, _ *string, _, _ int) ([]*ctemid.CTEMID, int, error) {
	return nil, len(r.byCTEMID), nil
}
func (r *fakeRepo) GetByCTEMID(_ context.Context, id string) (*ctemid.CTEMID, error) {
	if e, ok := r.byCTEMID[id]; ok {
		return e, nil
	}
	return nil, ctemid.ErrCTEMIDNotFound
}
func (r *fakeRepo) Count(_ context.Context) (int, error) { return len(r.byCTEMID), nil }

func TestParseCatalog_BareArray(t *testing.T) {
	body := []byte(`[
		{"ctem_id":"CTEM-1001","category":"lookalike domains","title":"acme-login.com","severity":"high","url":"https://ctem.org/1001","published_at":"2026-08-01T00:00:00Z"},
		{"id":"CTEM-1002","type":"ransomware","name":"LockBit affiliate","description":"observed"},
		{"category":"other","title":"missing id — dropped"},
		{"ctem_id":"CTEM-1003"}
	]`)
	entries, err := parseCatalog(body)
	if err != nil {
		t.Fatalf("parseCatalog: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 usable entries (id+title required), got %d", len(entries))
	}
	if entries[0].CTEMID() != "CTEM-1001" || entries[0].Category() != ctemid.CategoryLookalikeDomains {
		t.Errorf("entry0 = %s/%s", entries[0].CTEMID(), entries[0].Category())
	}
	if entries[0].PublishedAt() == nil {
		t.Errorf("entry0 published_at should parse")
	}
	if entries[1].CTEMID() != "CTEM-1002" || entries[1].Category() != ctemid.CategoryRansomware {
		t.Errorf("entry1 = %s/%s", entries[1].CTEMID(), entries[1].Category())
	}
	if entries[1].Title() != "LockBit affiliate" {
		t.Errorf("entry1 title coalesce failed: %q", entries[1].Title())
	}
}

func TestParseCatalog_WrapperObject(t *testing.T) {
	body := []byte(`{"source":[{"ctem_id":"CTEM-2001","category":"credential dumps","title":"dump-2001"}]}`)
	entries, err := parseCatalog(body)
	if err != nil {
		t.Fatalf("parseCatalog: %v", err)
	}
	if len(entries) != 1 || entries[0].Category() != ctemid.CategoryCredentialDumps {
		t.Fatalf("wrapper parse failed: %+v", entries)
	}
}

func TestUpsertBatch_Idempotent(t *testing.T) {
	repo := newFakeRepo()
	body := []byte(`[{"ctem_id":"CTEM-3001","category":"system exposure","title":"open rdp"}]`)
	entries, err := parseCatalog(body)
	if err != nil {
		t.Fatalf("parseCatalog: %v", err)
	}

	ctx := context.Background()
	if err := repo.UpsertBatch(ctx, entries); err != nil {
		t.Fatalf("upsert #1: %v", err)
	}
	// Re-ingest the same feed — count must not grow.
	entries2, _ := parseCatalog(body)
	if err := repo.UpsertBatch(ctx, entries2); err != nil {
		t.Fatalf("upsert #2: %v", err)
	}

	n, _ := repo.Count(ctx)
	if n != 1 {
		t.Fatalf("expected 1 catalog entry after idempotent re-ingest, got %d", n)
	}
}

func TestNewService_DefaultsURL(t *testing.T) {
	s := NewService(newFakeRepo(), "", testLogger())
	if s.FeedURL() != DefaultFeedURL {
		t.Errorf("feed URL = %q, want default %q", s.FeedURL(), DefaultFeedURL)
	}
	s2 := NewService(newFakeRepo(), "https://example.test/feed.json", testLogger())
	if s2.FeedURL() != "https://example.test/feed.json" {
		t.Errorf("feed URL override not honored: %q", s2.FeedURL())
	}
}
