package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	threatalertapp "github.com/openctemio/openctem/server/internal/app/threatalert"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/threatalert"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// fakeAlertStore answers for one organization; any other organization gets
// nothing (what the repository's tenant predicate does).
type fakeAlertStore struct {
	tenant     shared.ID
	alert      threatalert.Alert
	allInScope bool
	setCalls   int
	lastFilter threatalert.ListFilter
}

func (f *fakeAlertStore) List(_ context.Context, tid shared.ID, _ *shared.DataScope, flt threatalert.ListFilter) ([]threatalert.Alert, int, threatalert.Summary, error) {
	f.lastFilter = flt
	if tid != f.tenant {
		return nil, 0, threatalert.Summary{}, nil
	}
	return []threatalert.Alert{f.alert}, 1, threatalert.Summary{Open: 1}, nil
}

func (f *fakeAlertStore) Get(_ context.Context, tid shared.ID, _ *shared.DataScope, id shared.ID) (*threatalert.Detail, error) {
	if tid != f.tenant || id != f.alert.ID {
		return nil, threatalert.ErrNotFound
	}
	return &threatalert.Detail{Alert: f.alert, AllInScope: f.allInScope}, nil
}

func (f *fakeAlertStore) SetState(_ context.Context, tid, id shared.ID, to threatalert.State, _, _ string, _ shared.ID, _ time.Time, _ *time.Time) error {
	if tid != f.tenant || id != f.alert.ID {
		return threatalert.ErrNotFound
	}
	f.setCalls++
	f.alert.State = to
	return nil
}

type allowScope struct{}

func (allowScope) Resolve(context.Context, shared.ID) (*shared.DataScope, error) { return nil, nil }
func (allowScope) AssertAsset(context.Context, shared.ID, shared.ID) error       { return nil }

func emergingReq(method, target, body string, tenant shared.ID, id string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	ctx := context.WithValue(r.Context(), middleware.TenantIDKey, tenant.String())
	ctx = context.WithValue(ctx, middleware.UserIDKey, shared.NewID().String())
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(ctx, chi.RouteCtxKey, rc))
}

func TestEmergingThreatHandler(t *testing.T) {
	tenant := shared.NewID()
	store := &fakeAlertStore{tenant: tenant, alert: threatalert.Alert{ID: shared.NewID(), TenantID: tenant, VulnID: "CVE-2026-1",
		Level: threatalert.LevelImmediate, Tier: threatalert.TierConfirmed, State: threatalert.StateNew}}
	h := NewEmergingThreatHandler(threatalertapp.NewService(store, nil, logger.NewNop()), allowScope{}, logger.NewNop())
	do := func(fn http.HandlerFunc, r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		fn(w, r)
		return w
	}
	id := store.alert.ID.String()

	if w := do(h.List, emergingReq(http.MethodGet, "/api/v1/emerging-threats?level=urgent", "", tenant, "")); w.Code != http.StatusBadRequest {
		t.Fatalf("bad level: %d", w.Code)
	}
	if w := do(h.List, emergingReq(http.MethodGet, "/api/v1/emerging-threats?state=open&tier=possible", "", tenant, "")); w.Code != http.StatusOK ||
		len(store.lastFilter.States) != 3 || store.lastFilter.Tier != threatalert.TierPossible {
		t.Fatalf("list: %d %+v", w.Code, store.lastFilter)
	}
	if store.lastFilter.KEVOnly {
		t.Fatal("kev filter set without kev=true")
	}
	// kev=true keeps known-exploited alerts; the row carries the in-scope
	// product, the crown-jewel count and the score breakdown.
	store.alert.Product, store.alert.ProductCount, store.alert.Critical = "WordPress", 2, 1
	store.alert.Confirmed, store.alert.Likely, store.alert.Possible, store.alert.InternetFacing = 3, 1, 2, 2
	store.alert.Breakdown = threatalert.Breakdown{Exploitation: 40, Total: 40}
	w := do(h.List, emergingReq(http.MethodGet, "/api/v1/emerging-threats?kev=true", "", tenant, ""))
	if w.Code != http.StatusOK || !store.lastFilter.KEVOnly {
		t.Fatalf("kev list: %d %+v", w.Code, store.lastFilter)
	}
	for _, want := range []string{`"product":"WordPress"`, `"product_count":2`, `"critical_hosts":1`, `"ets_breakdown":{"exploitation":40`, `"new":0`,
		`"confirmed_hosts":3`, `"likely_hosts":1`, `"possible_hosts":2`, `"internet_facing_hosts":2`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("list body misses %s: %s", want, w.Body.String())
		}
	}
	// A host count is never named assets on the wire.
	if strings.Contains(w.Body.String(), `_assets"`) {
		t.Fatalf("list body names a host count assets: %s", w.Body.String())
	}
	if w := do(h.Get, emergingReq(http.MethodGet, "/", "", tenant, id)); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"can_suppress":false`) {
		t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}
	// Another organization: 404, never the alert.
	other := shared.NewID()
	if w := do(h.Get, emergingReq(http.MethodGet, "/", "", other, id)); w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get: %d", w.Code)
	}
	if w := do(h.SetState, emergingReq(http.MethodPost, "/", `{"state":"acknowledged"}`, other, id)); w.Code != http.StatusNotFound || store.setCalls != 0 {
		t.Fatalf("cross-tenant triage: %d (%d writes)", w.Code, store.setCalls)
	}
	if w := do(h.Get, emergingReq(http.MethodGet, "/", "", tenant, "not-a-uuid")); w.Code != http.StatusNotFound {
		t.Fatalf("bad id: %d", w.Code)
	}
	// Validation, unknown fields, out of scope.
	if w := do(h.SetState, emergingReq(http.MethodPost, "/", `{"state":"not_affected"}`, tenant, id)); w.Code != http.StatusBadRequest {
		t.Fatalf("no reason: %d", w.Code)
	}
	if w := do(h.SetState, emergingReq(http.MethodPost, "/", `{"state":"acknowledged","tenant_id":"x"}`, tenant, id)); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", w.Code)
	}
	if w := do(h.SetState, emergingReq(http.MethodPost, "/", `{"state":"not_affected","reason":"wrong_product"}`, tenant, id)); w.Code != http.StatusConflict || store.setCalls != 0 {
		t.Fatalf("out-of-scope suppression: %d (%d writes)", w.Code, store.setCalls)
	}
	if w := do(h.SetState, emergingReq(http.MethodPost, "/", `{"state":"acknowledged"}`, tenant, id)); w.Code != http.StatusOK || store.setCalls != 1 {
		t.Fatalf("acknowledge: %d", w.Code)
	}
	// No enforcer wired: refused, never unscoped.
	bare := NewEmergingThreatHandler(threatalertapp.NewService(store, nil, logger.NewNop()), nil, logger.NewNop())
	if w := do(bare.List, emergingReq(http.MethodGet, "/", "", tenant, "")); w.Code != http.StatusNotFound {
		t.Fatalf("no data scope enforcer: %d", w.Code)
	}
}

// The detail keeps the per-asset list and adds the same assets as one row
// per host; no asset, finding or task is lost on the way.
func TestToEmergingDetail_AssetGroups(t *testing.T) {
	tenant, finding, task := shared.NewID(), shared.NewID(), shared.NewID()
	view := func(name string, kind threatalert.MatchKind) threatalert.AssetView {
		return threatalert.AssetView{TenantID: tenant,
			Asset: threatalert.Asset{AssetID: shared.NewID(), Name: name, Type: "service", Kind: kind, Product: "nginx"}}
	}
	plain, tls, likely, box := view("http://192.0.2.20", threatalert.MatchConfirmed), view("https://192.0.2.20", threatalert.MatchConfirmed),
		view("https://example.com", threatalert.MatchLikely), view("web-01", threatalert.MatchLikely)
	tls.FindingID, tls.TaskID, tls.FindingStatus, tls.InternetFacing = &finding, &task, "confirmed", true

	out := toEmergingDetail(&threatalert.Detail{Assets: []threatalert.AssetView{plain, tls, likely, box}})
	if len(out.Assets) != 4 {
		t.Fatalf("the per-asset list stays: got %d", len(out.Assets))
	}
	if len(out.AssetGroups) != 2 || out.AssetGroups[0].Tier != "confirmed" || out.AssetGroups[1].Tier != "likely" {
		t.Fatalf("groups: %+v", out.AssetGroups)
	}
	host := out.AssetGroups[0].Hosts
	if len(host) != 1 || host[0].Host != "192.0.2.20" || host[0].AssetID != "" || !host[0].InternetFacing || len(host[0].Services) != 2 {
		t.Fatalf("confirmed hosts: %+v", host)
	}
	s := host[0].Services[1]
	if s.Label != "https" || s.AssetID != tls.AssetID.String() || s.FindingID != finding.String() || s.TaskID != task.String() ||
		s.FindingStatus != "confirmed" {
		t.Fatalf("service: %+v", s)
	}
	rows := out.AssetGroups[1].Hosts
	if len(rows) != 2 || rows[1].AssetID != box.AssetID.String() || rows[1].Services[0].Label != "" {
		t.Fatalf("likely hosts: %+v", rows)
	}
	if empty := toEmergingDetail(&threatalert.Detail{}); empty.AssetGroups == nil || len(empty.AssetGroups) != 0 {
		t.Fatalf("no assets: an empty list, not null")
	}
}
