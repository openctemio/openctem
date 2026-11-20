package threat

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/feedstatus"
	"github.com/openctemio/openctem/server/pkg/domain/threatintel"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type truthKEV struct {
	threatintel.KEVRepository
	count    int64
	upserted int
}

func (r *truthKEV) Count(context.Context) (int64, error) { return r.count, nil }
func (r *truthKEV) UpsertBatch(_ context.Context, e []*threatintel.KEVEntry) error {
	r.upserted += len(e)
	return nil
}
func (r *truthKEV) PruneNotIn(context.Context, []string) (int64, error) { return 0, nil }

type truthEPSS struct {
	threatintel.EPSSRepository
	count    int64
	upserted int
}

func (r *truthEPSS) Count(context.Context) (int64, error) { return r.count, nil }
func (r *truthEPSS) UpsertBatch(_ context.Context, e []*threatintel.EPSSScore) error {
	r.upserted += len(e)
	return nil
}

type truthStatus struct {
	threatintel.SyncStatusRepository
	st *threatintel.SyncStatus
	// held: another run holds the feed.
	held  bool
	tried int
}

func (r *truthStatus) GetBySource(context.Context, string) (*threatintel.SyncStatus, error) {
	return r.st, nil
}
func (r *truthStatus) TryStart(context.Context, string, time.Duration) (bool, error) {
	r.tried++
	if r.held {
		return false, nil
	}
	r.st.MarkSyncStarted()
	return true, nil
}
func (r *truthStatus) Update(context.Context, *threatintel.SyncStatus) error { return nil }

type truthRepo struct {
	threatintel.ThreatIntelRepository
	kev  *truthKEV
	epss *truthEPSS
	st   *truthStatus
}

func (r *truthRepo) KEV() threatintel.KEVRepository               { return r.kev }
func (r *truthRepo) EPSS() threatintel.EPSSRepository             { return r.epss }
func (r *truthRepo) SyncStatus() threatintel.SyncStatusRepository { return r.st }
func (r *truthRepo) PropagateToVulnerabilityCatalog(context.Context) (int64, error) {
	return 0, nil
}

func newTruthService(t *testing.T, now time.Time, meta map[string]any) (*IntelService, *truthRepo) {
	t.Helper()
	st := threatintel.ReconstituteSyncStatus(threatintel.NewSyncStatus("kev", 24).ID(), "kev", nil,
		threatintel.SyncStateSuccess, "", 1500, 0, nil, 24, true, meta, now, now)
	repo := &truthRepo{kev: &truthKEV{count: 1500}, epss: &truthEPSS{count: 300000}, st: &truthStatus{st: st}}
	s := NewIntelService(repo, logger.NewNop())
	s.now = func() time.Time { return now }
	return s, repo
}

// A release whose KEV copy the collector read recently is a successful
// check of the feed: its last success moves even though no data changed, so
// a current feed never looks stale only because CISA added nothing.
func TestRecordBundleSeen_RecentCopyIsASuccess(t *testing.T) {
	now := time.Now().UTC()
	s, repo := newTruthService(t, now, map[string]any{threatintel.MetaFailingSince: now.Add(-time.Hour).Format(time.RFC3339)})
	if err := s.RecordBundleSeen(context.Background(), "kev", BundleStream{FetchedAt: now.Add(-30 * time.Minute), Sequence: 94}); err != nil {
		t.Fatal(err)
	}
	st := repo.st.st
	if st.LastSyncStatus() != threatintel.SyncStateSuccess || st.Metadata()[threatintel.MetaLastSuccessAt] == nil {
		t.Fatalf("not a success: %v %v", st.LastSyncStatus(), st.Metadata())
	}
	if _, failing := st.Metadata()[threatintel.MetaFailingSince]; failing {
		t.Fatal("failure start kept after a success")
	}
	if st.RecordsSynced() != 1500 {
		t.Fatalf("stored count lost: %d", st.RecordsSynced())
	}
}

// A release can carry a copy the collector has not refreshed (the source
// blocked the collector, say): that is a failed check with its own code, so
// the console and the freshness alarms see it, never a silent success.
func TestRecordBundleSeen_OldCopyFails(t *testing.T) {
	now := time.Now().UTC()
	s, repo := newTruthService(t, now, map[string]any{})
	if err := s.RecordBundleSeen(context.Background(), "kev", BundleStream{FetchedAt: now.Add(-7 * time.Hour), Sequence: 94}); err != nil {
		t.Fatal(err)
	}
	st := repo.st.st
	if st.LastSyncStatus() != threatintel.SyncStateFailed || st.Metadata()[threatintel.MetaErrorCode] != feedstatus.CodeSourceStale {
		t.Fatalf("old copy: %v %v", st.LastSyncStatus(), st.Metadata())
	}
	if !errors.Is(ErrSourceStale, ErrSourceStale) || !strings.Contains(st.LastSyncError(), "the collector last read kev") {
		t.Fatalf("error text: %q", st.LastSyncError())
	}
}

// A refused stream (bad signature, truncated) marks the feed failed with the
// refusal's code.
func TestRecordBundleRefused_MarksTheFeedFailed(t *testing.T) {
	now := time.Now().UTC()
	s, repo := newTruthService(t, now, map[string]any{})
	s.RecordBundleRefused(context.Background(), "kev", feedstatus.Tag(feedstatus.CodeSignatureInvalid, nil, errors.New("bad signature")))
	st := repo.st.st
	if st.LastSyncStatus() != threatintel.SyncStateFailed || st.Metadata()[threatintel.MetaErrorCode] != feedstatus.CodeSignatureInvalid {
		t.Fatalf("refused: %v %v", st.LastSyncStatus(), st.Metadata())
	}
	if st.Metadata()[MetaBundleError] == nil {
		t.Fatal("bundle error not recorded")
	}
}

// The organization stats payload carries sync state, never the raw error text
// of a failed fetch.
func TestThreatIntelSyncDTO_HasNoErrorText(t *testing.T) {
	typ := reflect.TypeOf(ThreatIntelSyncDTO{})
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		if strings.Contains(tag, "error") {
			t.Fatalf("ThreatIntelSyncDTO field %s (%s) can carry raw error text", typ.Field(i).Name, tag)
		}
	}
}
