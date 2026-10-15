package routes

// A restricted (data-scoped) member sees a remediation campaign only through
// their scope (research 156 B10): the explicit finding ids and the asset id
// of the campaign's filter that are outside the scope are removed, and the
// organization-wide risk values are not shown. The remediation side table is
// joined to findings of the same tenant only.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/exposure"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"

	"net/http/httptest"
)

func TestRemediationCampaign_RestrictedViewerSeesOnlyTheirScope_DB(t *testing.T) {
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
	svc := exposure.NewRemediationCampaignService(postgres.NewRemediationCampaignRepository(db), log)
	svc.SetFindingCounter(postgres.NewFindingRepository(db))
	svc.SetFindingLister(postgres.NewFindingRepository(db))
	svc.SetDataScope(enforcer)
	router := infrahttp.NewChiRouter()
	registerRemediationCampaignRoutes(router, handler.NewRemediationCampaignHandler(svc, log), Middleware(h.dsAuth), nil, passthrough)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)

	// Explicit ids of FA (memberA's scope) and FB (not), the out-of-scope
	// asset B, and stored organization-wide risk values.
	campaign := shared.NewID()
	filter, _ := json.Marshal(map[string]any{
		"finding_ids": []string{h.findingA.String(), h.findingB.String()},
		"asset_id":    h.assetB.String(),
	})
	h.exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status, finding_filter, risk_score_before, risk_score_after, risk_reduction)
		VALUES ($1, $2, 'rc-viewer', 'active', $3, 80, 20, 60)`, campaign.String(), h.tenant.String(), string(filter))

	perms := strings.Join(append(append([]string{}, dsMemberPerms...), permission.RemediationRead.String()), ",")
	type wire struct {
		ID            string         `json:"id"`
		FindingFilter map[string]any `json:"finding_filter"`
		RiskBefore    *float64       `json:"risk_before"`
		RiskReduction *float64       `json:"risk_reduction"`
	}
	get := func(path, user string, admin bool, out any) int {
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
		if out != nil && resp.StatusCode == http.StatusOK {
			if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
				t.Fatal(err)
			}
		}
		return resp.StatusCode
	}
	view := func(user string, admin bool) []wire {
		t.Helper()
		var one wire
		if code := get("/api/v1/remediation/campaigns/"+campaign.String(), user, admin, &one); code != http.StatusOK {
			t.Fatalf("GET as %s = %d", user, code)
		}
		var page struct {
			Data []wire `json:"data"`
		}
		get("/api/v1/remediation/campaigns/", user, admin, &page)
		for _, c := range page.Data {
			if c.ID == campaign.String() {
				return []wire{one, c}
			}
		}
		t.Fatalf("campaign not listed for %s", user)
		return nil
	}
	ids := func(w wire) []string {
		raw, _ := w.FindingFilter["finding_ids"].([]any)
		out := make([]string, 0, len(raw))
		for _, v := range raw {
			out = append(out, v.(string))
		}
		return out
	}

	for i, w := range view(h.memberA.String(), false) {
		if got := ids(w); len(got) != 1 || got[0] != h.findingA.String() {
			t.Errorf("restricted view %d finding_ids = %v, want only the in-scope FA", i, got)
		}
		if _, ok := w.FindingFilter["asset_id"]; ok {
			t.Errorf("restricted view %d shows the out-of-scope asset_id", i)
		}
		if w.RiskBefore != nil || w.RiskReduction != nil {
			t.Errorf("restricted view %d shows organization-wide risk %v/%v", i, w.RiskBefore, w.RiskReduction)
		}
	}
	// A member without any scope row sees no ids at all.
	for i, w := range view(h.memberStrict.String(), false) {
		if got := ids(w); len(got) != 0 {
			t.Errorf("member without scope view %d finding_ids = %v, want none", i, got)
		}
	}
	// The owner sees the campaign as stored.
	for i, w := range view(h.owner.String(), true) {
		if got := ids(w); len(got) != 2 || w.FindingFilter["asset_id"] != h.assetB.String() || w.RiskBefore == nil || *w.RiskBefore != 80 {
			t.Errorf("owner view %d = ids %v asset %v risk %v, want the stored campaign", i, got, w.FindingFilter["asset_id"], w.RiskBefore)
		}
	}
	// The redaction is a view: nothing is written back.
	var stored string
	if err := h.db.QueryRowContext(context.Background(), `SELECT finding_filter::text FROM remediation_campaigns WHERE tenant_id = $1 AND id = $2`,
		h.tenant.String(), campaign.String()).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stored, h.findingB.String()) || !strings.Contains(stored, h.assetB.String()) {
		t.Errorf("stored filter changed by a read: %s", stored)
	}

	// Another tenant's campaign is not found.
	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'rcv-other', $2)`, other.String(), "rcv-other-"+other.String()[28:])
	t.Cleanup(func() { h.exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
	foreign := shared.NewID()
	h.exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status, finding_filter)
		VALUES ($1, $2, 'rcv-foreign', 'active', '{}')`, foreign.String(), other.String())
	if code := get("/api/v1/remediation/campaigns/"+foreign.String(), h.owner.String(), true, nil); code != http.StatusNotFound {
		t.Errorf("another tenant's campaign = %d, want 404", code)
	}
}

// A remediation key row is only ever joined to a finding of its own tenant.
func TestRemediationKeys_JoinStaysInTheTenant_DB(t *testing.T) {
	h := newDSHarness(t)
	ctx := context.Background()
	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'rk-other', $2)`, other.String(), "rk-other-"+other.String()[28:])
	t.Cleanup(func() { h.exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
	asset, finding := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'rk-asset', 'domain', 'public', 'high')`, asset.String(), other.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sca', 'rk', 'rk', 'high', $1::text, 'confirmed')`, finding.String(), other.String(), asset.String())
	// A key row filed under this tenant that points at the other tenant's
	// finding (a corrupt or forged row) must not count.
	h.exec(`INSERT INTO finding_remediation_keys (finding_id, tenant_id, remediation_key, title) VALUES ($1, $2, 'sca:rk-x', 'x')`,
		finding.String(), h.tenant.String())
	repo := postgres.NewFindingRemediationKeyRepository(&postgres.DB{DB: h.db})
	total, _, err := repo.CountByKey(ctx, h.tenant, "sca:rk-x", []string{"resolved"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		t.Fatalf("a key row of this tenant counted another tenant's finding: total %d", total)
	}
	groups, err := repo.ListGroups(ctx, h.tenant, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		if g.Key == "sca:rk-x" {
			t.Fatalf("group built from another tenant's finding: %+v", g)
		}
	}
}
