package routes

// Remediation campaign progress follows the viewer (research 24 §5.1, gap
// L-18): a restricted member reading a campaign sees the finding and resolved
// counts of their own in-scope findings, not the organization-wide counts the
// campaign stores. The stored counts (used for auto-complete) stay
// organization-wide.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestRemediationCampaignProgress_FollowsTheViewer_DB(t *testing.T) {
	h := newDSHarness(t)
	db := &postgres.DB{DB: h.db}
	log := logger.NewNop()
	tenantRepo := postgres.NewTenantRepository(db)
	enforcer := datascope.New(postgres.NewDataScopeRepository(db),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, log)
	enforcer.SetAdminLookup(func(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
		m, err := tenantRepo.GetMembership(ctx, userID, tenantID)
		if err != nil {
			return false, err
		}
		return m.IsOwner() || m.IsAdmin(), nil
	})
	svc := app.NewRemediationCampaignService(postgres.NewRemediationCampaignRepository(db), log)
	svc.SetFindingCounter(postgres.NewFindingRepository(db))
	svc.SetDataScope(enforcer)
	router := infrahttp.NewChiRouter()
	registerRemediationCampaignRoutes(router, handler.NewRemediationCampaignHandler(svc, log), Middleware(h.dsAuth), nil, passthrough)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)

	// FA (A1, memberA's scope) is resolved; FB (B1) is open. Both are high.
	h.exec(`UPDATE findings SET status = 'resolved', resolved_at = now() WHERE id = $1`, h.findingA.String())
	campaign := shared.NewID()
	h.exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status, finding_filter)
		VALUES ($1, $2, 'rc-scope', 'active', '{"severities": ["high"]}')`, campaign.String(), h.tenant.String())

	type campaignWire struct {
		ID            string  `json:"id"`
		FindingCount  int     `json:"finding_count"`
		ResolvedCount int     `json:"resolved_count"`
		Progress      float64 `json:"progress"`
	}
	perms := strings.Join(append(append([]string{}, dsMemberPerms...), permission.RemediationRead.String()), ",")
	get := func(path, user string, admin bool, out any) {
		t.Helper()
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+path, nil)
		r.Header.Set("X-Test-User", user)
		if admin {
			r.Header.Set("X-Test-Admin", "1")
		}
		r.Header.Set("X-Test-Perms", perms)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s as %s = %d", path, user, resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	listed := func(user string, admin bool) campaignWire {
		t.Helper()
		var page struct {
			Data []campaignWire `json:"data"`
		}
		get("/api/v1/remediation/campaigns/", user, admin, &page)
		for _, c := range page.Data {
			if c.ID == campaign.String() {
				return c
			}
		}
		t.Fatalf("campaign not listed for %s", user)
		return campaignWire{}
	}

	for _, c := range []struct {
		name            string
		user            string
		admin           bool
		total, resolved int
	}{
		{"owner", h.owner.String(), true, 2, 1},
		{"full-data role", h.memberFull.String(), false, 2, 1},
		{"restricted member", h.memberA.String(), false, 1, 1},
		{"member without a group", h.memberStrict.String(), false, 0, 0},
	} {
		var got campaignWire
		get("/api/v1/remediation/campaigns/"+campaign.String(), c.user, c.admin, &got)
		if got.FindingCount != c.total || got.ResolvedCount != c.resolved {
			t.Errorf("%s GET campaign = %d/%d, want %d/%d", c.name, got.ResolvedCount, got.FindingCount, c.resolved, c.total)
		}
		if l := listed(c.user, c.admin); l.FindingCount != c.total || l.ResolvedCount != c.resolved {
			t.Errorf("%s list campaign = %d/%d, want %d/%d", c.name, l.ResolvedCount, l.FindingCount, c.resolved, c.total)
		}
	}
	// The stored counts stay organization-wide (auto-complete reads them):
	// a restricted reader never persists their view.
	var fc, rc int
	if err := h.db.QueryRowContext(context.Background(), `SELECT finding_count, resolved_count FROM remediation_campaigns WHERE id = $1`, campaign.String()).Scan(&fc, &rc); err != nil {
		t.Fatal(err)
	}
	if fc != 2 || rc != 1 {
		t.Errorf("stored counts = %d/%d, want the organization's 1/2", rc, fc)
	}
}
