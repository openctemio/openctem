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
	// memberA created it, so they see it although its findings, filtered by
	// FA/FB AND asset B, are all outside their scope.
	h.exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status, finding_filter, risk_score_before, risk_score_after, risk_reduction, created_by)
		VALUES ($1, $2, 'rc-viewer', 'active', $3, 80, 20, 60, $4)`, campaign.String(), h.tenant.String(), string(filter), h.memberA.String())

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
	// A member without any scope row does not see the campaign at all.
	if code := get("/api/v1/remediation/campaigns/"+campaign.String(), h.memberStrict.String(), false, nil); code != http.StatusNotFound {
		t.Errorf("member without scope GET = %d, want 404", code)
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

// A restricted member can neither read nor change a campaign that does not
// touch their data scope: every read and write answers 404 and the campaign
// is not listed. A campaign over their own findings, or one they created,
// stays fully usable.
func TestRemediationCampaign_RestrictedMemberCannotTouchOtherTeamsCampaign_DB(t *testing.T) {
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
	epics := &refusingEpicCreator{t: t}
	svc.SetTicketing(postgres.NewRemediationCampaignTicketRepository(db), epics)
	router := infrahttp.NewChiRouter()
	registerRemediationCampaignRoutes(router, handler.NewRemediationCampaignHandler(svc, log), Middleware(h.dsAuth), nil, passthrough)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)

	insert := func(name string, filter map[string]any) shared.ID {
		id := shared.NewID()
		raw, _ := json.Marshal(filter)
		h.exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status, finding_filter)
			VALUES ($1, $2, $3, 'active', $4)`, id.String(), h.tenant.String(), name, string(raw))
		return id
	}
	// Another team's campaigns: over FB (asset B), and over asset B by id.
	otherTeam := insert("rcw-other-findings", map[string]any{"finding_ids": []string{h.findingB.String()}})
	otherAsset := insert("rcw-other-asset", map[string]any{"asset_id": h.assetB.String(), "severities": []string{"critical"}})
	mine := insert("rcw-mine", map[string]any{"finding_ids": []string{h.findingA.String()}})

	perms := strings.Join(append(append([]string{}, dsMemberPerms...),
		permission.RemediationRead.String(), permission.RemediationWrite.String(), permission.FindingsFixApply.String()), ",")
	call := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rd *strings.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = strings.NewReader(string(b))
		} else {
			rd = strings.NewReader("")
		}
		r, _ := http.NewRequestWithContext(context.Background(), method, srv.URL+path, rd)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Test-User", h.memberA.String())
		r.Header.Set("X-Test-Perms", perms)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	for _, id := range []shared.ID{otherTeam, otherAsset} {
		base := "/api/v1/remediation/campaigns/" + id.String()
		for _, c := range []struct {
			method, path string
			body         any
		}{
			{http.MethodGet, base, nil},
			{http.MethodGet, base + "/findings", nil},
			{http.MethodPatch, base, map[string]any{"name": "taken over"}},
			{http.MethodPatch, base + "/status", map[string]any{"status": "paused"}},
			{http.MethodPost, base + "/resolve", map[string]any{"status": "fix_applied", "resolution": "done"}},
			{http.MethodPost, base + "/refresh", nil},
			{http.MethodPost, base + "/create-ticket", map[string]any{"project_key": "SEC"}},
			{http.MethodDelete, base, nil},
		} {
			if code, _ := call(c.method, c.path, c.body); code != http.StatusNotFound {
				t.Errorf("%s %s by a member outside its scope = %d, want 404", c.method, c.path, code)
			}
		}
		var name, status string
		if err := h.db.QueryRowContext(context.Background(), `SELECT name, status FROM remediation_campaigns WHERE tenant_id = $1 AND id = $2`,
			h.tenant.String(), id.String()).Scan(&name, &status); err != nil {
			t.Fatalf("campaign %s gone after the refused calls: %v", id, err)
		}
		if name == "taken over" || status != "active" {
			t.Errorf("campaign %s changed by refused calls: %s/%s", id, name, status)
		}
	}

	// The list shows only campaigns that touch the member's scope, and its
	// total counts only those.
	_, page := call(http.MethodGet, "/api/v1/remediation/campaigns/", nil)
	listed := map[string]bool{}
	data, _ := page["data"].([]any)
	for _, d := range data {
		listed[d.(map[string]any)["id"].(string)] = true
	}
	if listed[otherTeam.String()] || listed[otherAsset.String()] || !listed[mine.String()] {
		t.Errorf("restricted list = %v, want only the member's campaign", listed)
	}
	if page["total"] != float64(len(listed)) {
		t.Errorf("restricted list total = %v, want %d", page["total"], len(listed))
	}

	// Their own campaign stays usable, and so does an empty one they create.
	if code, _ := call(http.MethodPatch, "/api/v1/remediation/campaigns/"+mine.String(), map[string]any{"name": "mine renamed"}); code != http.StatusOK {
		t.Errorf("PATCH the member's campaign = %d, want 200", code)
	}
	code, created := call(http.MethodPost, "/api/v1/remediation/campaigns/", map[string]any{"name": "rcw-new", "priority": "high"})
	if code != http.StatusCreated {
		t.Fatalf("create = %d %v", code, created)
	}
	if code, _ := call(http.MethodGet, "/api/v1/remediation/campaigns/"+created["id"].(string), nil); code != http.StatusOK {
		t.Errorf("GET the campaign the member created = %d, want 200", code)
	}
}

// refusingEpicCreator fails the test if an epic is created or moved: the
// refused calls must stop before reaching the tracker.
type refusingEpicCreator struct{ t *testing.T }

func (r *refusingEpicCreator) CreateEpic(context.Context, shared.ID, string, string, string, []string) (string, string, error) {
	r.t.Error("an epic was created for a campaign outside the caller's scope")
	return "", "", nil
}

func (r *refusingEpicCreator) TransitionEpic(context.Context, shared.ID, string, string, string) error {
	return nil
}
