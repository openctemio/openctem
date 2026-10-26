package threat

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/logger"
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

type roundTrip func(*http.Request) *http.Response

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r), nil }

func resp(code int, body string, h map[string]string) *http.Response {
	r := &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return r
}

func newTruthService(t *testing.T, rt roundTrip, kevStored, epssStored int64, recordsSynced int, meta map[string]any) (*IntelService, *truthRepo) {
	t.Helper()
	st := threatintel.ReconstituteSyncStatus(threatintel.NewSyncStatus("kev", 24).ID(), "kev", nil,
		threatintel.SyncStateSuccess, "", recordsSynced, 0, nil, 24, true, meta, time.Now(), time.Now())
	repo := &truthRepo{kev: &truthKEV{count: kevStored}, epss: &truthEPSS{count: epssStored}, st: &truthStatus{st: st}}
	s := NewIntelService(repo, logger.NewNop())
	s.httpClient = &http.Client{Transport: rt}
	return s, repo
}

// An unchanged catalog (304) must not overwrite the stored count with zero.
func TestSyncKEV_NotModifiedKeepsCount(t *testing.T) {
	meta := map[string]any{kevValidatorsKey: map[string]any{kevURL: map[string]any{"etag": `"v1"`}}}
	s, repo := newTruthService(t, func(*http.Request) *http.Response { return resp(304, "", nil) }, 1512, 0, 1512, meta)
	r := s.SyncKEV(context.Background())
	if r.Error != nil || !r.NotModified {
		t.Fatalf("result: %+v", r)
	}
	if got := repo.st.st.RecordsSynced(); got != 1512 {
		t.Fatalf("records_synced = %d, want 1512 kept", got)
	}
}

// A count an earlier run already overwrote with zero is repaired from the catalog.
func TestSyncKEV_NotModifiedHealsZeroCount(t *testing.T) {
	meta := map[string]any{kevValidatorsKey: map[string]any{kevURL: map[string]any{"etag": `"v1"`}}}
	s, repo := newTruthService(t, func(*http.Request) *http.Response { return resp(304, "", nil) }, 1512, 0, 0, meta)
	if r := s.SyncKEV(context.Background()); r.Error != nil {
		t.Fatal(r.Error)
	}
	if got := repo.st.st.RecordsSynced(); got != 1512 {
		t.Fatalf("records_synced = %d, want 1512 healed", got)
	}
}

// A 200 with an empty or renamed array is a failure, never "success, 0", and
// its validators are not stored.
func TestSyncKEV_EmptyFeedFails(t *testing.T) {
	for name, body := range map[string]string{
		"empty array": `{"vulnerabilities":[]}`,
		"renamed key": `{"items":[{"cveID":"CVE-2026-0001"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			s, repo := newTruthService(t, func(*http.Request) *http.Response {
				return resp(200, body, map[string]string{"ETag": `"bad"`})
			}, 1512, 0, 1512, map[string]any{})
			r := s.SyncKEV(context.Background())
			if !errors.Is(r.Error, ErrFeedEmpty) {
				t.Fatalf("error = %v, want ErrFeedEmpty", r.Error)
			}
			if repo.st.st.LastSyncStatus() != threatintel.SyncStateFailed {
				t.Fatalf("status = %v", repo.st.st.LastSyncStatus())
			}
			if _, ok := repo.st.st.Metadata()[kevValidatorsKey]; ok {
				t.Fatal("validators of the bad response were stored")
			}
			if repo.kev.upserted != 0 {
				t.Fatal("entries written from an empty feed")
			}
		})
	}
}

func kevJSON(n int) string {
	var b strings.Builder
	b.WriteString(`{"vulnerabilities":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"cveID":"CVE-2026-%04d","vulnerabilityName":"x","dateAdded":"2026-10-19"}`, i)
	}
	b.WriteString(`]}`)
	return b.String()
}

func TestSyncKEV_ShrinkGuard(t *testing.T) {
	s, repo := newTruthService(t, func(*http.Request) *http.Response { return resp(200, kevJSON(80), nil) },
		100, 0, 100, map[string]any{})
	r := s.SyncKEV(context.Background())
	if !errors.Is(r.Error, ErrFeedShrunk) {
		t.Fatalf("error = %v, want ErrFeedShrunk", r.Error)
	}
	if repo.kev.upserted != 0 || repo.st.st.LastSyncStatus() != threatintel.SyncStateFailed {
		t.Fatalf("upserted %d, status %v", repo.kev.upserted, repo.st.st.LastSyncStatus())
	}
	// 95 of 100 (above 90 %) is accepted.
	s, repo = newTruthService(t, func(*http.Request) *http.Response { return resp(200, kevJSON(95), nil) },
		100, 0, 100, map[string]any{})
	if r := s.SyncKEV(context.Background()); r.Error != nil || repo.kev.upserted != 95 {
		t.Fatalf("result %+v upserted %d", r, repo.kev.upserted)
	}
}

func epssGz(n int) *bytes.Buffer {
	var raw strings.Builder
	raw.WriteString("#model_version:v2025.03.14,score_date:2026-10-25\ncve,epss,percentile\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&raw, "CVE-2026-%04d,0.01,0.5\n", i)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(raw.String()))
	_ = zw.Close()
	return &buf
}

func TestSyncEPSS_ShrinkGuardAndEmpty(t *testing.T) {
	serve := func(n int) roundTrip {
		return func(*http.Request) *http.Response {
			r := resp(200, "", nil)
			r.Body = io.NopCloser(epssGz(n))
			return r
		}
	}
	s, repo := newTruthService(t, serve(50), 0, 100, 0, map[string]any{})
	if r := s.SyncEPSS(context.Background()); !errors.Is(r.Error, ErrFeedShrunk) || repo.epss.upserted != 0 {
		t.Fatalf("shrink: %+v upserted %d", r, repo.epss.upserted)
	}
	s, repo = newTruthService(t, serve(0), 0, 100, 0, map[string]any{})
	if r := s.SyncEPSS(context.Background()); !errors.Is(r.Error, ErrFeedEmpty) || repo.epss.upserted != 0 {
		t.Fatalf("empty: %+v", r)
	}
	s, repo = newTruthService(t, serve(95), 0, 100, 0, map[string]any{})
	if r := s.SyncEPSS(context.Background()); r.Error != nil || repo.epss.upserted != 95 {
		t.Fatalf("ok: %+v upserted %d", r, repo.epss.upserted)
	}
}

// A run that finds the feed held by another does not fetch, write or touch
// the status: the scheduled run and an operator's request never overlap.
func TestSync_SkipsWhenAnotherRunHoldsTheFeed(t *testing.T) {
	fetched := false
	rt := func(*http.Request) *http.Response { fetched = true; return resp(200, kevJSON(5), nil) }
	s, repo := newTruthService(t, rt, 5, 5, 5, map[string]any{})
	repo.st.held = true
	for name, r := range map[string]IntelSyncResult{
		"kev":  s.SyncKEV(context.Background()),
		"epss": s.SyncEPSS(context.Background()),
	} {
		if !r.Skipped || !errors.Is(r.Error, threatintel.ErrSyncAlreadyRunning) {
			t.Fatalf("%s: %+v", name, r)
		}
	}
	if fetched || repo.kev.upserted != 0 || repo.epss.upserted != 0 {
		t.Fatalf("a skipped run fetched=%v wrote kev=%d epss=%d", fetched, repo.kev.upserted, repo.epss.upserted)
	}
	if repo.st.st.LastSyncStatus() != threatintel.SyncStateSuccess {
		t.Fatalf("status changed to %s", repo.st.st.LastSyncStatus())
	}
	// Free again: it runs.
	repo.st.held = false
	if r := s.SyncKEV(context.Background()); r.Skipped || r.Error != nil || !fetched {
		t.Fatalf("free: %+v", r)
	}
}
