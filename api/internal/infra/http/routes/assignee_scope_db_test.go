package routes

// Being assigned grants view of the assigned item (docs/architecture/
// authorization-matrix.md, "Data scope"): the assignee of a finding sees that
// finding, never its asset or the asset's other findings; the assignee of a
// remediation campaign sees the campaign and the findings it tracks, but may
// not change it beyond their own scope. Unassigning removes the view at once;
// other members are unaffected. Requires DATABASE_URL.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
)

func TestAssigneeScope_FindingAssigneeSeesOnlyTheAssignedFinding(t *testing.T) {
	h := newDSHarness(t)
	sam := h.memberStrict // no group, no grant, owns nothing
	fa, fb := h.findingA.String(), h.findingB.String()
	status := func(user shared.ID, path string) int {
		t.Helper()
		s, _ := h.do(user, false, http.MethodGet, path, nil)
		return s
	}

	if s := status(sam, "/api/v1/findings/"+fb); s != http.StatusNotFound {
		t.Fatalf("before assignment GET finding = %d, want 404", s)
	}
	h.exec(`UPDATE findings SET assigned_to = $2 WHERE id = $1`, fb, sam.String())

	if s := status(sam, "/api/v1/findings/"+fb); s != http.StatusOK {
		t.Errorf("assignee GET assigned finding = %d, want 200", s)
	}
	// Never the asset or the asset's other findings.
	if s := status(sam, "/api/v1/assets/"+h.assetB.String()); s != http.StatusNotFound {
		t.Errorf("assignee GET the finding's asset = %d, want 404", s)
	}
	if s := status(sam, "/api/v1/findings/"+fa); s != http.StatusNotFound {
		t.Errorf("assignee GET an unassigned finding = %d, want 404", s)
	}
	code, body := h.do(sam, false, http.MethodGet, "/api/v1/findings/", nil)
	if code != http.StatusOK || !strings.Contains(body, fb) || strings.Contains(body, fa) {
		t.Errorf("assignee findings list = %d, want only the assigned finding (%.300s)", code, body)
	}
	// Other members are unaffected.
	if s := status(h.memberFree, "/api/v1/findings/"+fb); s != http.StatusNotFound {
		t.Errorf("another member GET = %d, want 404", s)
	}
	// An organization API key (no user) never matches an assignee.
	if s := status(shared.ID{}, "/api/v1/findings/"+fb); s != http.StatusNotFound {
		t.Errorf("organization key GET = %d, want 404", s)
	}

	// Unassigned: the view goes at once.
	h.exec(`UPDATE findings SET assigned_to = NULL WHERE id = $1`, fb)
	if s := status(sam, "/api/v1/findings/"+fb); s != http.StatusNotFound {
		t.Errorf("ex-assignee GET = %d, want 404", s)
	}
	code, body = h.do(sam, false, http.MethodGet, "/api/v1/findings/", nil)
	if code != http.StatusOK || strings.Contains(body, fb) {
		t.Errorf("ex-assignee findings list still has the finding (%.300s)", body)
	}
}

// The assignee check is tenant-scoped: a finding of another tenant assigned
// (by bad data) to a member never shows in that member's tenant.
func TestAssigneeScope_CrossTenant(t *testing.T) {
	h := newDSHarness(t)
	other, otherAsset, otherFinding := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "as-"+other.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'as-other.example', 'domain')`, otherAsset.String(), other.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, assigned_to)
		VALUES ($1::uuid, $2, $3, 'sast', 't', 'as other tenant', 'critical', $1::text, 'confirmed', $4)`,
		otherFinding.String(), other.String(), otherAsset.String(), h.memberStrict.String())
	if s, body := h.do(h.memberStrict, false, http.MethodGet, "/api/v1/findings/"+otherFinding.String(), nil); s != http.StatusNotFound {
		t.Errorf("another tenant's finding assigned to the member = %d, want 404 (%.200s)", s, body)
	}
	if _, body := h.do(h.memberStrict, false, http.MethodGet, "/api/v1/findings/", nil); strings.Contains(body, otherFinding.String()) {
		t.Errorf("findings list leaked another tenant's finding")
	}
}

func TestAssigneeScope_CampaignAssigneeSeesCampaignAndItsFindings(t *testing.T) {
	h := newDSHarness(t)
	db := &postgres.DB{DB: h.db}
	log := logger.NewNop()
	enforcer := datascope.New(postgres.NewDataScopeRepository(db),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, log)
	svc := exposure.NewRemediationCampaignService(postgres.NewRemediationCampaignRepository(db), log)
	svc.SetFindingCounter(postgres.NewFindingRepository(db))
	svc.SetFindingLister(postgres.NewFindingRepository(db))
	svc.SetDataScope(enforcer)
	router := infrahttp.NewChiRouter()
	registerRemediationCampaignRoutes(router, handler.NewRemediationCampaignHandler(svc, log), Middleware(h.dsAuth), nil, passthrough)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)

	sam := h.memberStrict
	campaign := shared.NewID()
	// Created by a member who sees every asset (memberFull): only such a
	// creator widens the assignee's view to the campaign's findings.
	h.exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status, finding_filter, assigned_to, created_by)
		VALUES ($1, $2, 'as-campaign', 'active', '{"severities": ["high"], "tool_name": "ds-tool"}', $3, $4)`,
		campaign.String(), h.tenant.String(), sam.String(), h.memberFull.String())
	// The same filter, created by a restricted member (memberA) or by Sam
	// himself, assigned to Sam: the campaign is his, its findings outside
	// his scope are not (a live filter must not open other teams' findings).
	restricted, self := shared.NewID(), shared.NewID()
	for id, by := range map[shared.ID]shared.ID{restricted: h.memberA, self: sam} {
		h.exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status, finding_filter, assigned_to, created_by)
			VALUES ($1::uuid, $2, 'as-campaign-'||$1::text, 'active', '{"severities": ["high"], "tool_name": "ds-tool"}', $3, $4)`,
			id.String(), h.tenant.String(), sam.String(), by.String())
	}

	perms := strings.Join(append(append([]string{}, dsMemberPerms...), permission.RemediationRead.String(), permission.RemediationWrite.String()), ",")
	call := func(method, path string, user shared.ID, body any) (int, string) {
		t.Helper()
		var rdr *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		} else {
			rdr = bytes.NewReader(nil)
		}
		r, _ := http.NewRequestWithContext(context.Background(), method, srv.URL+path, rdr)
		r.Header.Set("X-Test-User", user.String())
		r.Header.Set("X-Test-Perms", perms)
		r.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.String()
	}
	base := "/api/v1/remediation/campaigns/"
	id := campaign.String()

	// The assignee: listed, readable, and the campaign's findings (both).
	if s, body := call(http.MethodGet, base, sam, nil); s != http.StatusOK || !strings.Contains(body, id) {
		t.Errorf("assignee campaign list = %d, want the campaign (%.300s)", s, body)
	}
	if s, body := call(http.MethodGet, base+id, sam, nil); s != http.StatusOK || !strings.Contains(body, `"finding_count":2`) {
		t.Errorf("assignee GET campaign = %d, want 200 with 2 findings (%.300s)", s, body)
	}
	s, body := call(http.MethodGet, base+id+"/findings", sam, nil)
	if s != http.StatusOK || !strings.Contains(body, h.findingA.String()) || !strings.Contains(body, h.findingB.String()) {
		t.Errorf("assignee campaign findings = %d, want both findings (%.300s)", s, body)
	}
	for _, c := range []shared.ID{restricted, self} {
		if s, body := call(http.MethodGet, base+c.String(), sam, nil); s != http.StatusOK || !strings.Contains(body, `"finding_count":0`) {
			t.Errorf("assignee GET campaign by a restricted creator = %d, want 200 with 0 findings (%.300s)", s, body)
		}
		if s, body := call(http.MethodGet, base+c.String()+"/findings", sam, nil); s != http.StatusOK ||
			strings.Contains(body, h.findingA.String()) || strings.Contains(body, h.findingB.String()) {
			t.Errorf("assignee findings of a campaign by a restricted creator = %d, want none (%.300s)", s, body)
		}
	}
	// View, not change: the campaign covers findings outside Sam's scope.
	if s, body := call(http.MethodPatch, base+id, sam, map[string]any{"name": "renamed"}); s != http.StatusForbidden && s != http.StatusNotFound {
		t.Errorf("assignee PATCH campaign = %d, want refused (%.200s)", s, body)
	}

	// Another member: not listed, 404.
	if s, body := call(http.MethodGet, base, h.memberFree, nil); s != http.StatusOK || strings.Contains(body, id) {
		t.Errorf("other member campaign list = %d, must not list it (%.300s)", s, body)
	}
	if s, _ := call(http.MethodGet, base+id, h.memberFree, nil); s != http.StatusNotFound {
		t.Errorf("other member GET campaign = %d, want 404", s)
	}

	// Unassigned: the view goes.
	h.exec(`UPDATE remediation_campaigns SET assigned_to = NULL WHERE id = $1`, id)
	if s, _ := call(http.MethodGet, base+id, sam, nil); s != http.StatusNotFound {
		t.Errorf("ex-assignee GET campaign = %d, want 404", s)
	}
	if s, body := call(http.MethodGet, base+id+"/findings", sam, nil); s != http.StatusNotFound {
		t.Errorf("ex-assignee campaign findings = %d, want 404 (%.200s)", s, body)
	}
}
