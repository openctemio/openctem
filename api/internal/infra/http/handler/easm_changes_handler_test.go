package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/easmchange"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeChangeLister struct {
	tenants []shared.ID
	q       easmchange.Query
}

func (f *fakeChangeLister) List(_ context.Context, id shared.ID, q easmchange.Query) (*easmchange.Page, error) {
	f.tenants = append(f.tenants, id)
	f.q = q
	if err := q.Normalize(time.Now()); err != nil {
		return nil, err
	}
	return &easmchange.Page{From: q.From, To: q.To, Counts: map[easmchange.Kind]int{}, Items: []easmchange.Change{}}, nil
}

// The change feed reads the token's tenant, parses the window, kinds and
// limit, and answers 400 for bad input.
func TestEASMChangesHandler(t *testing.T) {
	tenantID := shared.NewID()
	lister := &fakeChangeLister{}
	h := NewEASMHandler(nil, logger.NewNop()).SetChanges(lister)

	w := httptest.NewRecorder()
	h.Changes(w, seedReq(http.MethodGet, "/?from=2026-10-01T00:00:00Z&to=2026-10-08T00:00:00Z&kind=host_added,dns_dangling&limit=20", "", tenantID, "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	if lister.tenants[0] != tenantID || len(lister.q.Kinds) != 2 || lister.q.Limit != 20 ||
		lister.q.From != time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("query: %+v", lister.q)
	}
	for _, bad := range []string{"/?kind=nope", "/?from=yesterday", "/?limit=0", "/?limit=x",
		"/?from=2026-01-01T00:00:00Z&to=2026-03-01T00:00:00Z"} {
		w = httptest.NewRecorder()
		h.Changes(w, seedReq(http.MethodGet, bad, "", tenantID, "u1"))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, w.Code)
		}
	}
}

// Digest settings: on by default with Monday, omitted fields keep their
// value, a weekday outside 1..7 is refused.
func TestEASMSettingsDigest(t *testing.T) {
	tenantID := shared.NewID()
	store := &fakeEASMSettingsStore{es: tenant.EASMSettings{EnrichmentDisabled: true}}
	h := NewEASMSettingsHandler(store, nil, &fakeSweeper{}, EASMPlatform{}, &settingsAudit{}, logger.NewNop())

	w := httptest.NewRecorder()
	h.Get(w, seedReq(http.MethodGet, "/", "", tenantID, "u1"))
	if !strings.Contains(w.Body.String(), `"weekly_digest_enabled":true`) || !strings.Contains(w.Body.String(), `"digest_weekday":1`) {
		t.Fatalf("defaults: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	h.Update(w, seedReq(http.MethodPut, "/", `{"ct_enabled":true,"dns_checks_enabled":true,"weekly_digest_enabled":false,"digest_weekday":7}`, tenantID, "u1"))
	if w.Code != http.StatusOK || !store.es.WeeklyDigestDisabled || store.es.DigestWeekday != 7 || !store.es.EnrichmentDisabled {
		t.Fatalf("update: %d %+v", w.Code, store.es)
	}
	if !strings.Contains(w.Body.String(), `"digest_weekday":7`) {
		t.Fatalf("sunday not echoed: %s", w.Body.String())
	}
	// Omitted digest fields keep their value.
	w = httptest.NewRecorder()
	h.Update(w, seedReq(http.MethodPut, "/", `{"ct_enabled":true,"dns_checks_enabled":true}`, tenantID, "u1"))
	if w.Code != http.StatusOK || !store.es.WeeklyDigestDisabled || store.es.DigestWeekday != 7 {
		t.Fatalf("omitted fields changed: %+v", store.es)
	}
	saved := store.saved
	w = httptest.NewRecorder()
	h.Update(w, seedReq(http.MethodPut, "/", `{"ct_enabled":true,"dns_checks_enabled":true,"digest_weekday":9}`, tenantID, "u1"))
	if w.Code != http.StatusBadRequest || store.saved != saved {
		t.Fatalf("weekday 9: %d", w.Code)
	}
}
