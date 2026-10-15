package routes

// A campaign's finding_filter decides which findings its resolve changes. Over
// the real routes, handler, services and a migrated database:
//   - an unparseable condition is refused (400), never dropped: a dropped
//     asset_id next to a severity meant every finding of that severity in the
//     organization (the "whole tenant" widening);
//   - a status alone is not scope;
//   - resolving needs findings:fix_apply on the route as well as the campaign
//     write, and changes only findings in the caller's data scope.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/exposure"
	"github.com/openctemio/openctem/api/internal/app/finding"
	appremediation "github.com/openctemio/openctem/api/internal/app/remediation"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type campaignFilterHarness struct {
	*dsHarness
	srv      *httptest.Server
	critical shared.ID // FC: a critical finding on B1, outside memberA's scope
}

func newCampaignFilterHarness(t *testing.T) *campaignFilterHarness {
	t.Helper()
	ds := newDSHarness(t)
	db := &postgres.DB{DB: ds.db}
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
	findingRepo := postgres.NewFindingRepository(db)
	accessRepo := postgres.NewAccessControlRepository(db)
	vuln := finding.NewVulnerabilityService(postgres.NewVulnerabilityRepository(db), findingRepo, log)
	vuln.SetAccessControlRepository(accessRepo)
	vuln.SetDataScope(enforcer)
	actions := finding.NewFindingActionsService(findingRepo, accessRepo, nil, postgres.NewAssetRepository(db), nil, ds.db, log)
	vuln.SetFixApplierCheck(actions.FixAppliers)

	svc := exposure.NewRemediationCampaignService(postgres.NewRemediationCampaignRepository(db), log)
	svc.SetFindingCounter(findingRepo)
	svc.SetFindingLister(findingRepo)
	svc.SetDataScope(enforcer)
	svc.SetFindingResolver(appremediation.NewCampaignFilterResolver(vuln, nil))
	router := infrahttp.NewChiRouter()
	registerRemediationCampaignRoutes(router, handler.NewRemediationCampaignHandler(svc, log), Middleware(ds.dsAuth), nil, passthrough)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)

	h := &campaignFilterHarness{dsHarness: ds, srv: srv, critical: shared.NewID()}
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sast', 'ds-tool', 'critical elsewhere', 'critical', $1::text, 'confirmed')`,
		h.critical.String(), h.tenant.String(), h.assetB.String())
	return h
}

func (h *campaignFilterHarness) call(user shared.ID, admin bool, perms []string, method, path string, body any) (int, string) {
	h.t.Helper()
	b, _ := json.Marshal(body)
	r, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, bytes.NewReader(b))
	if err != nil {
		h.t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Test-User", user.String())
	if admin {
		r.Header.Set("X-Test-Admin", "1")
	}
	r.Header.Set("X-Test-Perms", strings.Join(perms, ","))
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

// storedCampaign inserts an active campaign with a filter as an older
// version could have saved it (no strict check at the time).
func (h *campaignFilterHarness) storedCampaign(filter string) string {
	h.t.Helper()
	id := shared.NewID().String()
	h.exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status, finding_filter) VALUES ($1, $2, 'cf', 'active', $3::jsonb)`,
		id, h.tenant.String(), filter)
	return id
}

func campaignWritePerms(fixApply bool) []string {
	p := append([]string{}, dsMemberPerms...)
	p = append(p, permission.RemediationRead.String(), permission.RemediationWrite.String(), permission.FindingsStatus.String())
	if fixApply {
		p = append(p, permission.FindingsFixApply.String())
	}
	return p
}

func (h *campaignFilterHarness) status(id shared.ID) string {
	h.t.Helper()
	var s string
	if err := h.db.QueryRow(`SELECT status FROM findings WHERE id = $1`, id.String()).Scan(&s); err != nil {
		h.t.Fatal(err)
	}
	return s
}

// The whole-tenant exploit: a filter whose asset_id does not parse used to
// keep only the severity, so the campaign covered (and resolved) every
// critical finding of the organization.
func TestCampaignFilter_InvalidConditionNeverWidens(t *testing.T) {
	h := newCampaignFilterHarness(t)
	perms := campaignWritePerms(true)
	exploit := map[string]any{"asset_id": "not-a-uuid", "severity": "critical"}

	// Saving such a filter is refused, on create and on update.
	if st, body := h.call(h.owner, true, perms, http.MethodPost, "/api/v1/remediation/campaigns/",
		map[string]any{"name": "cf", "finding_filter": exploit}); st != http.StatusBadRequest {
		t.Errorf("create with an unparseable asset_id = %d %.300s, want 400", st, body)
	}
	ok := h.storedCampaign(`{"finding_ids": ["` + h.findingA.String() + `"]}`)
	if st, body := h.call(h.owner, true, perms, http.MethodPatch, "/api/v1/remediation/campaigns/"+ok,
		map[string]any{"finding_filter": exploit}); st != http.StatusBadRequest {
		t.Errorf("update with an unparseable asset_id = %d %.300s, want 400", st, body)
	}
	for _, f := range []map[string]any{{"owner": "x"}, {"severity": "urgent"}, {"severity": 3}} {
		if st, body := h.call(h.owner, true, perms, http.MethodPost, "/api/v1/remediation/campaigns/",
			map[string]any{"name": "cf", "finding_filter": f}); st != http.StatusBadRequest {
			t.Errorf("create with %v = %d %.200s, want 400", f, st, body)
		}
	}

	// A stored filter like that tracks nothing and cannot resolve; the
	// critical finding it would have reached is untouched.
	h.exec(`UPDATE findings SET assigned_to = $2 WHERE id = $1`, h.critical.String(), h.owner.String())
	bad := h.storedCampaign(`{"asset_id": "not-a-uuid", "severity": "critical"}`)
	st, body := h.call(h.owner, true, perms, http.MethodPost, "/api/v1/remediation/campaigns/"+bad+"/resolve",
		map[string]any{"resolution": "patched"})
	if st != http.StatusBadRequest {
		t.Errorf("resolve of a stored unparseable filter = %d %.300s, want 400", st, body)
	}
	if got := h.status(h.critical); got != "confirmed" {
		t.Fatalf("WIDENED: the stored filter's resolve changed a critical finding outside its asset to %s", got)
	}
	var c struct {
		FindingCount int `json:"finding_count"`
	}
	st, body = h.call(h.owner, true, perms, http.MethodGet, "/api/v1/remediation/campaigns/"+bad, nil)
	if st != http.StatusOK || json.Unmarshal([]byte(body), &c) != nil || c.FindingCount != 0 {
		t.Errorf("stored unparseable filter counts %d findings (%d %.200s), want 0", c.FindingCount, st, body)
	}
}

// A status alone is the whole organization: not scope.
func TestCampaignFilter_StatusOnlyIsNotScope(t *testing.T) {
	h := newCampaignFilterHarness(t)
	h.exec(`UPDATE findings SET assigned_to = $2 WHERE tenant_id = $1`, h.tenant.String(), h.owner.String())
	id := h.storedCampaign(`{"statuses": ["confirmed"]}`)
	st, body := h.call(h.owner, true, campaignWritePerms(true), http.MethodPost, "/api/v1/remediation/campaigns/"+id+"/resolve",
		map[string]any{"resolution": "patched"})
	if st != http.StatusBadRequest {
		t.Errorf("resolve of a status-only campaign = %d %.300s, want 400", st, body)
	}
	for _, f := range []shared.ID{h.findingA, h.findingB, h.critical} {
		if got := h.status(f); got != "confirmed" {
			t.Errorf("a status-only campaign changed %s to %s", f, got)
		}
	}
}

// Resolving needs findings:fix_apply on the route, and a restricted member
// changes only the findings in their data scope.
func TestCampaignResolve_NeedsFixApplyAndStaysInScope(t *testing.T) {
	h := newCampaignFilterHarness(t)
	h.exec(`UPDATE findings SET assigned_to = $2 WHERE id IN ($1, $3)`, h.findingA.String(), h.memberA.String(), h.findingB.String())
	id := h.storedCampaign(`{"severity": "high"}`)
	path := "/api/v1/remediation/campaigns/" + id + "/resolve"

	if st, body := h.call(h.memberA, false, campaignWritePerms(false), http.MethodPost, path,
		map[string]any{"resolution": "patched"}); st != http.StatusForbidden {
		t.Errorf("resolve without findings:fix_apply = %d %.300s, want 403", st, body)
	}
	if got := h.status(h.findingA); got != "confirmed" {
		t.Fatalf("a refused resolve changed FA to %s", got)
	}

	st, body := h.call(h.memberA, false, campaignWritePerms(true), http.MethodPost, path, map[string]any{"resolution": "patched"})
	if st != http.StatusOK || !strings.Contains(body, `"updated":1`) {
		t.Fatalf("restricted resolve = %d %.300s, want 1 updated", st, body)
	}
	if strings.Contains(body, h.findingB.String()) {
		t.Errorf("the response names an out-of-scope finding: %.300s", body)
	}
	if got := h.status(h.findingA); got != "fix_applied" {
		t.Errorf("in-scope FA = %s, want fix_applied", got)
	}
	if got := h.status(h.findingB); got != "confirmed" {
		t.Errorf("out-of-scope FB changed to %s", got)
	}
}
