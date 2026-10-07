package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeEASMSettingsStore struct {
	es      tenant.EASMSettings
	tenants []string
	saved   int
}

func (f *fakeEASMSettingsStore) GetEASMSettings(_ context.Context, id string) (*tenant.EASMSettings, error) {
	f.tenants = append(f.tenants, id)
	es := f.es
	return &es, nil
}

func (f *fakeEASMSettingsStore) UpdateEASMSettings(_ context.Context, id string, es tenant.EASMSettings, _ auditapp.AuditContext) (*tenant.EASMSettings, error) {
	f.tenants = append(f.tenants, id)
	f.saved++
	f.es = es
	return &es, nil
}

type fakeSweeper struct {
	until   time.Time
	tooSoon bool
	tenants []shared.ID
}

func (f *fakeSweeper) RunNow(_ context.Context, id shared.ID) (*easmapp.SweepTicket, time.Time, error) {
	f.tenants = append(f.tenants, id)
	if f.tooSoon {
		return nil, f.until, easmapp.ErrSweepTooSoon
	}
	return &easmapp.SweepTicket{StartedAt: time.Now(), CTIncluded: true, DNSIncluded: true}, time.Time{}, nil
}

// research/22 P0-11: settings are read and written for the token's tenant,
// the floor is enforced (1 h → 400, nothing saved), run-now answers 202 and
// is audited, and a second one within 15 minutes is 429 with Retry-After.
func TestEASMSettingsHandler(t *testing.T) {
	tenantID := shared.NewID()
	store := &fakeEASMSettingsStore{es: tenant.EASMSettings{CTDisabled: true}}
	sw := &fakeSweeper{}
	aud := &settingsAudit{}
	h := NewEASMSettingsHandler(store, nil, sw, EASMPlatform{CTAvailable: true, DNSAvailable: true, CTDefaultHrs: 24, DNSDefaultHrs: 24}, aud, logger.NewNop())

	w := httptest.NewRecorder()
	h.Get(w, seedReq(http.MethodGet, "/", "", tenantID, "u1"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ct_enabled":false`) ||
		!strings.Contains(w.Body.String(), `"dns_checks_enabled":true`) || !strings.Contains(w.Body.String(), `"ct_effective_interval_hours":24`) {
		t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	h.Update(w, seedReq(http.MethodPut, "/", `{"ct_enabled":true,"dns_checks_enabled":true,"ct_interval_hours":1}`, tenantID, "u1"))
	if w.Code != http.StatusBadRequest || store.saved != 0 {
		t.Fatalf("floor: %d saved=%d", w.Code, store.saved)
	}
	w = httptest.NewRecorder()
	h.Update(w, seedReq(http.MethodPut, "/", `{"ct_enabled":true,"dns_checks_enabled":false,"ct_interval_hours":6}`, tenantID, "u1"))
	if w.Code != http.StatusOK || store.es.CTDisabled || !store.es.DNSChecksDisabled || store.es.CTIntervalHours != 6 {
		t.Fatalf("update: %d %+v", w.Code, store.es)
	}
	for _, id := range store.tenants {
		if id != tenantID.String() {
			t.Fatal("another tenant reached the store")
		}
	}

	w = httptest.NewRecorder()
	h.RunNow(w, seedReq(http.MethodPost, "/", "", tenantID, "u1"))
	if w.Code != http.StatusAccepted || len(sw.tenants) != 1 || sw.tenants[0] != tenantID {
		t.Fatalf("run-now: %d %v", w.Code, sw.tenants)
	}
	if len(aud.actions) != 1 || aud.actions[0] != auditdom.ActionEASMSweepRequested {
		t.Fatalf("audit = %v", aud.actions)
	}
	sw.tooSoon, sw.until = true, time.Now().Add(10*time.Minute)
	w = httptest.NewRecorder()
	h.RunNow(w, seedReq(http.MethodPost, "/", "", tenantID, "u1"))
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" || len(aud.actions) != 1 {
		t.Fatalf("second run-now: %d %q audits=%d", w.Code, w.Header().Get("Retry-After"), len(aud.actions))
	}
}

type settingsAudit struct{ actions []auditdom.Action }

func (c *settingsAudit) LogEvent(_ context.Context, _ auditapp.AuditContext, e auditapp.AuditEvent) error {
	c.actions = append(c.actions, e.Action)
	return nil
}

func seedReq(method, target, body string, tenant shared.ID, user string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
	ctx = context.WithValue(ctx, middleware.UserIDKey, user)
	return req.WithContext(ctx)
}
