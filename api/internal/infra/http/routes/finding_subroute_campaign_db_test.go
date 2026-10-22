package routes

// The pentest campaign gate on every sub-resource of a finding (research 225
// S1). The finding itself is refused to non-members by the finding service;
// the guard now applies the same rule to /findings/{id}/** so AI triage,
// approvals, ticket links and the rest are as closed as the finding. The test
// runs the real DataScopeGuard, enforcer and repository against a migrated
// database and a stub handler on each real sub-route path.

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// findingSubRoutes are the sub-routes of a finding that read or send finding
// content. The final entry is a route that does not exist: the gate is
// path-based, so a route added later is covered too.
//
//nolint:gochecknoglobals // fixture
var findingSubRoutes = []struct{ name, method, suffix string }{
	{"ai-triage latest", http.MethodGet, "/ai-triage"},
	{"ai-triage send to model", http.MethodPost, "/ai-triage"},
	{"ai-triage history", http.MethodGet, "/ai-triage/history"},
	{"ai-triage result", http.MethodGet, "/ai-triage/" + "00000000-0000-7000-8000-000000000001"},
	{"activity", http.MethodGet, "/activities"},
	{"approvals", http.MethodGet, "/approvals"},
	{"ticket links", http.MethodGet, "/ticket-links"},
	{"ticket holds", http.MethodGet, "/ticket-holds"},
	{"priority explanation", http.MethodGet, "/priority-explanation"},
	{"comments", http.MethodGet, "/comments"},
	{"a future sub-route", http.MethodGet, "/not-yet-built"},
}

type campaignHarness struct {
	t                                                  *testing.T
	db                                                 *sql.DB
	srv                                                *httptest.Server
	tenant                                             shared.ID
	lead, client, outsider, admin                      shared.ID
	published, unpublished, noCampaign, genericFinding shared.ID
}

func newCampaignHarness(t *testing.T) *campaignHarness {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping campaign gate DB test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	h := &campaignHarness{t: t, db: db, tenant: shared.NewID(),
		lead: shared.NewID(), client: shared.NewID(), outsider: shared.NewID(), admin: shared.NewID()}
	h.seed()

	enforcer := datascope.New(postgres.NewDataScopeRepository(&postgres.DB{DB: db}),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, logger.NewNop())
	guard := middleware.DataScopeGuard(enforcer)
	stub := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	authed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), middleware.UserIDKey, r.Header.Get("X-Test-User"))
		ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenant.String())
		ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
		guard(stub).ServeHTTP(w, r.WithContext(ctx))
	})
	h.srv = httptest.NewServer(authed)
	t.Cleanup(h.srv.Close)
	return h
}

func (h *campaignHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %q: %v", q, err)
	}
}

func (h *campaignHarness) seed() {
	camp := shared.NewID()
	h.published, h.unpublished, h.noCampaign, h.genericFinding = shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	asset := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, h.tenant.String(), "cg-"+h.tenant.String())
	for _, u := range []shared.ID{h.lead, h.client, h.outsider, h.admin} {
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'member')`, u.String(), u.String()+"@cg.test")
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, u.String(), h.tenant.String())
	}
	h.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, h.tenant.String())
		for _, u := range []shared.ID{h.lead, h.client, h.outsider, h.admin} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u.String())
		}
	})
	h.exec(`INSERT INTO pentest_campaigns (id, tenant_id, name) VALUES ($1, $2, 'engagement')`, camp.String(), h.tenant.String())
	h.exec(`INSERT INTO pentest_campaign_members (tenant_id, campaign_id, user_id, role) VALUES ($1, $2, $3, 'lead'), ($1, $2, $4, 'client')`,
		h.tenant.String(), camp.String(), h.lead.String(), h.client.String())
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, 'a.example.com', 'domain', 'active')`, asset.String(), h.tenant.String())
	ins := func(id shared.ID, source, status string, campaign any, assetID any) {
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, rule_id, message, severity, fingerprint, status, pentest_campaign_id)
			VALUES ($1::uuid, $2, $3, $4, 't', 'r', 'm', 'high', $1::text, $5, $6)`,
			id.String(), h.tenant.String(), assetID, source, status, campaign)
	}
	ins(h.published, "pentest", "confirmed", camp.String(), asset.String())
	ins(h.unpublished, "pentest", "draft", camp.String(), asset.String())
	ins(h.noCampaign, "pentest", "confirmed", nil, asset.String())
	ins(h.genericFinding, "dast", "confirmed", nil, asset.String())
	// Everyone is in the asset data scope: only the campaign decides.
	// (A pentest finding may carry an inventory asset; the scope check still applies.)
	for _, u := range []shared.ID{h.lead, h.client, h.outsider} {
		h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
			u.String(), h.tenant.String(), asset.String())
	}
}

func (h *campaignHarness) do(user shared.ID, admin bool, method, path string) int {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("X-Test-User", user.String())
	if admin {
		req.Header.Set("X-Test-Admin", "1")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestFindingSubRoutes_NonMemberOfPentestCampaignGets404(t *testing.T) {
	h := newCampaignHarness(t)
	for _, rt := range findingSubRoutes {
		t.Run(rt.name, func(t *testing.T) {
			base := "/api/v1/findings/"
			pub := base + h.published.String() + rt.suffix
			if got := h.do(h.outsider, false, rt.method, pub); got != http.StatusNotFound {
				t.Errorf("non-member %s %s = %d, want 404", rt.method, pub, got)
			}
			if got := h.do(h.lead, false, rt.method, pub); got != http.StatusOK {
				t.Errorf("campaign lead %s = %d, want to pass the gate (200)", pub, got)
			}
			if got := h.do(h.client, false, rt.method, pub); got != http.StatusOK {
				t.Errorf("client on a published finding %s = %d, want 200", pub, got)
			}
			// A client never reaches an unpublished finding or its sub-resources.
			unpub := base + h.unpublished.String() + rt.suffix
			if got := h.do(h.client, false, rt.method, unpub); got != http.StatusNotFound {
				t.Errorf("client on unpublished %s = %d, want 404", unpub, got)
			}
			// An organization admin passes; a pentest finding with no campaign is admin-only.
			if got := h.do(h.admin, true, rt.method, base+h.noCampaign.String()+rt.suffix); got != http.StatusOK {
				t.Errorf("admin on campaign-less pentest finding = %d, want 200", got)
			}
			if got := h.do(h.lead, false, rt.method, base+h.noCampaign.String()+rt.suffix); got != http.StatusNotFound {
				t.Errorf("member on campaign-less pentest finding = %d, want 404", got)
			}
			// The gate leaves ordinary findings to the asset data scope.
			if got := h.do(h.outsider, false, rt.method, base+h.genericFinding.String()+rt.suffix); got != http.StatusOK {
				t.Errorf("in-scope member on a non-pentest finding = %d, want 200", got)
			}
		})
	}
}

func TestFindingSubRoutes_CampaignGateAlsoCoversOtherFindingPrefixes(t *testing.T) {
	h := newCampaignHarness(t)
	for _, p := range []string{"/api/v1/compliance/findings/", "/api/v1/verification-checklists/"} {
		if got := h.do(h.outsider, false, http.MethodGet, p+h.published.String()+"/x"); got != http.StatusNotFound {
			t.Errorf("non-member GET %s = %d, want 404", p, got)
		}
	}
}
