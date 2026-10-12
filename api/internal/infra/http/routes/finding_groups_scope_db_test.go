package routes

// Layer 2 data scope on the grouped findings view (GET /findings/groups),
// its "related CVEs" side panel and the Pending Review (fix_applied) queue's
// verify / reject-by-filter actions, over the real routes, handlers,
// services and a migrated database.
//
// The group listings used to aggregate over the whole tenant: a member whose
// scope is asset A1 saw group B's asset name, CVE ids, owner, component and
// the counts those findings contribute, and could verify or reopen group B's
// fix_applied findings by CVE.

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/finding"
	appremediation "github.com/openctemio/openctem/api/internal/app/remediation"
	savedviewapp "github.com/openctemio/openctem/api/internal/app/savedview"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/savedview"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

const (
	gsMarkerOwnerB     = "dsB-SECRET owner"
	gsMarkerComponentB = "dsb-secret-lib"
	gsComponentA       = "dsa-lib"
)

// gsHarness is the data-scope harness plus the rows the group dimensions need.
type gsHarness struct {
	*dsHarness
	ownerB                       shared.ID // owns asset B1
	findingB2, findingP          shared.ID // FB2: B1 sharing A's component; FP: pentest on A1
	cveA, cveB, cveB2, cveP      string
	componentA, componentB, camp shared.ID
	vuln                         *finding.VulnerabilityService
	views                        *savedviewapp.Service
}

func newGroupScopeHarness(t *testing.T) *gsHarness {
	t.Helper()
	// newDSHarness seeds the tenant, users, A1/B1, FA/FB and memberA's scope
	// (and skips without a test database); this harness serves its own router
	// with the finding actions handler mounted.
	ds := newDSHarness(t)
	h := &gsHarness{dsHarness: ds}
	h.seedGroups()

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
	assetRepo := postgres.NewAssetRepository(db)
	accessRepo := postgres.NewAccessControlRepository(db)

	vulnSvc := finding.NewVulnerabilityService(postgres.NewVulnerabilityRepository(db), findingRepo, log)
	vulnSvc.SetAccessControlRepository(accessRepo)
	vulnSvc.SetDataScope(enforcer)
	vulnSvc.SetAssetRepository(assetRepo)
	vulnSvc.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))
	h.vuln = vulnSvc

	actionsSvc := finding.NewFindingActionsService(findingRepo, accessRepo, nil, assetRepo, nil, ds.db, log)
	actionsSvc.SetDataScope(enforcer)

	remediationSvc := appremediation.NewGroupService(postgres.NewFindingRemediationKeyRepository(db), vulnSvc, nil, log)
	remediationSvc.SetDataScope(enforcer)

	prevGuard := dataScopeGuardMiddleware
	dataScopeGuardMiddleware = middleware.DataScopeGuard(enforcer)
	t.Cleanup(func() { dataScopeGuardMiddleware = prevGuard })

	// The verify / reject actions read the acting user from the synced local user.
	auth := Middleware(func(next http.Handler) http.Handler {
		return ds.dsAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if id, err := shared.IDFromString(r.Header.Get("X-Test-User")); err == nil {
				if u, err := userdom.NewLocalUserWithID(id, id.String()+"@ds.test", "t"); err == nil {
					ctx = context.WithValue(ctx, middleware.LocalUserKey, u)
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		}))
	})
	// Saved views (D15) on the same router, so ?view=<id> runs end to end.
	viewSvc := savedviewapp.NewService(postgres.NewSavedViewRepository(db), map[string]savedviewapp.PageConfig{
		savedview.PageFindings: {Registry: vulnerability.FindingFields, Permission: permission.FindingsRead.String(),
			GroupBy: vulnerability.FindingGroupDimensions(), Extra: []string{"branch_status"}},
	}, log)
	viewSvc.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))
	h.views = viewSvc
	vulnHandler := handler.NewVulnerabilityHandler(vulnSvc, validator.New(), log)
	vulnHandler.SetSavedViews(viewSvc)
	actionsHandler := handler.NewFindingActionsHandler(actionsSvc, log)
	actionsHandler.SetSavedViews(viewSvc)

	router := infrahttp.NewChiRouter()
	registerVulnerabilityRoutes(router, vulnHandler,
		actionsHandler, nil, handler.NewRemediationGroupHandler(remediationSvc), auth, nil)
	registerSavedViewRoutes(router, handler.NewSavedViewHandler(viewSvc, log), auth, nil)
	ds.srv.Close()
	ds.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(ds.srv.Close)
	return h
}

func (h *gsHarness) seedGroups() {
	t := h.tenant.String()
	h.ownerB, h.findingB2, h.findingP = shared.NewID(), shared.NewID(), shared.NewID()
	h.componentA, h.componentB, h.camp = shared.NewID(), shared.NewID(), shared.NewID()
	// Unique per run (the vulnerability catalog is global) and well-formed
	// (CVE-YYYY-NNNNN), so related-cves accepts them.
	n := 100000 + rand.IntN(800000) //nolint:gosec // test fixture id, not security relevant
	h.cveA, h.cveB, h.cveB2, h.cveP = fmt.Sprintf("CVE-2099-%d1", n), fmt.Sprintf("CVE-2099-%d2", n),
		fmt.Sprintf("CVE-2099-%d3", n), fmt.Sprintf("CVE-2099-%d4", n)

	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, h.ownerB.String(), h.ownerB.String()+"@ds.test", gsMarkerOwnerB)
	h.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, h.ownerB.String())
		_, _ = h.db.ExecContext(ctx, `DELETE FROM software_products WHERE id IN (SELECT product_id FROM software_versions WHERE id IN ($1, $2))`,
			h.componentA.String(), h.componentB.String())
	})
	// B1's owner is a member of the tenant: only a member can be a finding's
	// assignee (assign-to-owners).
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, h.ownerB.String(), t)
	// Primary user owners (asset_owners is the only owner store; 'owner_ref'
	// rows do not grant data scope, so the scope under test is unchanged).
	h.exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, 'primary', 'owner_ref')`, h.assetA.String(), h.memberA.String())
	h.exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, 'primary', 'owner_ref')`, h.assetB.String(), h.ownerB.String())
	for id, name := range map[shared.ID]string{h.componentA: gsComponentA, h.componentB: gsMarkerComponentB} {
		testdb.InsertPackageVersion(h.t, h.db, "", id.String(), "pkg:npm/"+name+"-"+id.String()+"@1.0.0")
	}
	// FA: in scope. FB: out of scope, different value in every dimension.
	h.exec(`UPDATE findings SET cve_id = $2, component_id = $3, finding_type = 'vulnerability' WHERE id = $1`,
		h.findingA.String(), h.cveA, h.componentA.String())
	h.exec(`UPDATE findings SET cve_id = $2, component_id = $3, finding_type = 'secret', severity = 'critical', source = 'dast' WHERE id = $1`,
		h.findingB.String(), h.cveB, h.componentB.String())
	// FB2: out of scope, but shares A's component (and so A's type), so a
	// shared group's counts would include it.
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, cve_id, component_id, finding_type)
		VALUES ($1::uuid, $2, $3, 'sast', 'ds-tool', 'dsB-SECRET second finding', 'high', $1::text, 'confirmed', $4, $5, 'vulnerability')`,
		h.findingB2.String(), t, h.assetB.String(), h.cveB2, h.componentA.String())
	// FP: a pentest finding on in-scope A1, in a campaign memberA is not on.
	h.exec(`INSERT INTO pentest_campaigns (id, tenant_id, name) VALUES ($1, $2, 'ds-campaign')`, h.camp.String(), t)
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, cve_id, finding_type, pentest_campaign_id)
		VALUES ($1::uuid, $2, $3, 'pentest', 'manual', 'dsP pentest finding', 'high', $1::text, 'confirmed', $4, 'vulnerability', $5)`,
		h.findingP.String(), t, h.assetA.String(), h.cveP, h.camp.String())
}

type gsGroupsResponse struct {
	Data []struct {
		GroupKey string `json:"group_key"`
		Label    string `json:"label"`
		Stats    struct {
			Total          int `json:"total"`
			AffectedAssets int `json:"affected_assets"`
		} `json:"stats"`
	} `json:"data"`
	Pagination struct {
		Total int `json:"total"`
	} `json:"pagination"`
}

func (h *gsHarness) groups(user shared.ID, admin bool, query string) (gsGroupsResponse, string) {
	h.t.Helper()
	status, body := h.do(user, admin, http.MethodGet, "/api/v1/findings/groups?"+query, nil)
	if status != http.StatusOK {
		h.t.Fatalf("GET /findings/groups?%s = %d (body %.300s)", query, status, body)
	}
	var out gsGroupsResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		h.t.Fatalf("decode groups: %v (body %.300s)", err, body)
	}
	return out, body
}

func gsKeys(r gsGroupsResponse) []string {
	keys := make([]string, 0, len(r.Data))
	for _, g := range r.Data {
		keys = append(keys, g.GroupKey)
	}
	sort.Strings(keys)
	return keys
}

// gsDimension is one group_by value with the group keys an in-scope member
// and an unrestricted caller should see.
type gsDimension struct {
	groupBy  string
	scoped   string   // the only key memberA may see
	all      []string // keys an unrestricted caller sees (sorted)
	leakText []string // strings only out-of-scope rows produce
}

func (h *gsHarness) dimensions() []gsDimension {
	return []gsDimension{
		{"asset_id", h.assetA.String(), sorted(h.assetA.String(), h.assetB.String()), []string{dsMarkerAssetB}},
		{"cve_id", h.cveA, sorted(h.cveA, h.cveB, h.cveB2), []string{h.cveB, h.cveB2, h.cveP}},
		{"owner_id", h.memberA.String(), sorted(h.memberA.String(), h.ownerB.String()), []string{gsMarkerOwnerB}},
		{"component_id", h.componentA.String(), sorted(h.componentA.String(), h.componentB.String()), []string{gsMarkerComponentB}},
		{"severity", "high", sorted("critical", "high"), nil},
		{"source", "sast", sorted("dast", "sast"), nil},
		{"finding_type", "vulnerability", sorted("secret", "vulnerability"), nil},
	}
}

func sorted(s ...string) []string {
	sort.Strings(s)
	return s
}

func TestFindingGroups_ScopedMemberSeesOnlyInScopeGroupsAndCounts(t *testing.T) {
	h := newGroupScopeHarness(t)
	for _, d := range h.dimensions() {
		t.Run(d.groupBy, func(t *testing.T) {
			res, body := h.groups(h.memberA, false, "group_by="+d.groupBy)
			if keys := gsKeys(res); len(keys) != 1 || keys[0] != d.scoped {
				t.Errorf("memberA groups = %v, want only [%s]", keys, d.scoped)
			}
			if res.Pagination.Total != 1 {
				t.Errorf("memberA total groups = %d, want 1", res.Pagination.Total)
			}
			for _, g := range res.Data {
				// FA is the only in-scope finding on any group: counts derived
				// from FB / FB2 (same component, type, severity) must not show.
				if g.Stats.Total != 1 || g.Stats.AffectedAssets != 1 {
					t.Errorf("memberA group %s stats total=%d affected_assets=%d, want 1/1", g.GroupKey, g.Stats.Total, g.Stats.AffectedAssets)
				}
			}
			for _, m := range d.leakText {
				if strings.Contains(body, m) {
					t.Errorf("memberA group_by=%s leaked %q", d.groupBy, m)
				}
			}
		})
	}
}

func TestFindingGroups_AdminAndUnrestrictedMemberUnchanged(t *testing.T) {
	h := newGroupScopeHarness(t)
	for _, who := range []struct {
		name  string
		user  shared.ID
		admin bool
	}{{"owner", h.owner, true}, {"full-data role", h.memberFull, false}} {
		for _, d := range h.dimensions() {
			res, _ := h.groups(who.user, who.admin, "group_by="+d.groupBy)
			if got := gsKeys(res); strings.Join(got, ",") != strings.Join(d.all, ",") {
				t.Errorf("%s group_by=%s = %v, want %v", who.name, d.groupBy, got, d.all)
			}
			if res.Pagination.Total != len(d.all) {
				t.Errorf("%s group_by=%s total = %d, want %d", who.name, d.groupBy, res.Pagination.Total, len(d.all))
			}
		}
		// The shared component counts both its findings (FA and FB2).
		res, _ := h.groups(who.user, who.admin, "group_by=component_id")
		for _, g := range res.Data {
			if g.GroupKey == h.componentA.String() && g.Stats.Total != 2 {
				t.Errorf("%s component A total = %d, want 2", who.name, g.Stats.Total)
			}
		}
	}
}

func TestFindingGroups_PolicyNothing_MemberWithoutGroupSeesNoGroups(t *testing.T) {
	h := newGroupScopeHarness(t)
	for _, d := range h.dimensions() {
		res, _ := h.groups(h.memberStrict, false, "group_by="+d.groupBy)
		if len(res.Data) != 0 || res.Pagination.Total != 0 {
			t.Errorf("policy nothing, member without group: group_by=%s = %v (total %d), want none", d.groupBy, gsKeys(res), res.Pagination.Total)
		}
	}
	// Administrators are not affected by the policy.
	if res, _ := h.groups(h.owner, true, "group_by=asset_id"); res.Pagination.Total != 2 {
		t.Errorf("policy nothing: owner sees %d asset groups, want 2", res.Pagination.Total)
	}
}

// Pentest findings never appear on the generic grouped view, including for a
// member whose asset scope covers the finding's asset (campaign membership,
// not asset scope, governs pentest visibility).
func TestFindingGroups_PentestFindingNotShownToNonCampaignMember(t *testing.T) {
	h := newGroupScopeHarness(t)
	for _, q := range []string{"group_by=cve_id", "group_by=source", "group_by=cve_id&sources=pentest"} {
		_, body := h.groups(h.memberA, false, q)
		if strings.Contains(body, h.cveP) || strings.Contains(body, `"pentest"`) {
			t.Errorf("memberA %s shows the pentest finding: %.300s", q, body)
		}
	}
	if status, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/findings/related-cves/"+h.cveA, nil); status != http.StatusOK || strings.Contains(body, h.cveP) {
		t.Errorf("memberA related CVEs = %d, shows the pentest CVE: %.300s", status, body)
	}
}

func TestFindingGroups_RelatedCVEsScoped(t *testing.T) {
	h := newGroupScopeHarness(t)
	path := "/api/v1/findings/related-cves/" + url.PathEscape(h.cveA)
	status, body := h.do(h.memberA, false, http.MethodGet, path, nil)
	if status != http.StatusOK || strings.Contains(body, h.cveB2) {
		t.Errorf("memberA related CVEs of %s = %d, leaked out-of-scope %s: %.300s", h.cveA, status, h.cveB2, body)
	}
	// Asking about an out-of-scope CVE reveals nothing either.
	if _, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/findings/related-cves/"+h.cveB2, nil); strings.Contains(body, h.cveA) {
		t.Errorf("memberA related CVEs of out-of-scope %s listed %s: %.300s", h.cveB2, h.cveA, body)
	}
	for _, who := range []struct {
		name  string
		user  shared.ID
		admin bool
	}{{"owner", h.owner, true}, {"full-data role", h.memberFull, false}} {
		if status, body := h.do(who.user, who.admin, http.MethodGet, path, nil); status != http.StatusOK || !strings.Contains(body, h.cveB2) {
			t.Errorf("%s related CVEs of %s = %d, want %s listed: %.300s", who.name, h.cveA, status, h.cveB2, body)
		}
	}
}

// The Pending Review tab: groups of fix_applied findings and the verify /
// reject-fix actions that act on a whole group by CVE.
func TestFindingGroups_VerificationQueueScoped(t *testing.T) {
	h := newGroupScopeHarness(t)
	h.exec(`UPDATE findings SET status = 'fix_applied' WHERE id IN ($1, $2)`, h.findingA.String(), h.findingB.String())

	res, _ := h.groups(h.memberA, false, "group_by=cve_id&statuses=fix_applied")
	if keys := gsKeys(res); len(keys) != 1 || keys[0] != h.cveA || res.Pagination.Total != 1 {
		t.Errorf("memberA fix_applied queue = %v (total %d), want only [%s]", keys, res.Pagination.Total, h.cveA)
	}
	if res, _ := h.groups(h.owner, true, "group_by=cve_id&statuses=fix_applied"); res.Pagination.Total != 2 {
		t.Errorf("owner fix_applied queue total = %d, want 2", res.Pagination.Total)
	}

	// Reject by filter naming B's CVE: nothing in scope, FB untouched.
	status, body := h.do(h.memberA, false, http.MethodPost, "/api/v1/findings/actions/reject-fix",
		map[string]any{"filter": map[string]any{"cve_ids": []string{h.cveB}}, "reason": "not fixed"})
	if status != http.StatusOK || !strings.Contains(body, `"updated":0`) {
		t.Errorf("memberA reject-fix B by filter = %d %.200s, want updated 0", status, body)
	}
	if st, _, _ := h.findingState(h.findingB); st != "fix_applied" {
		t.Errorf("out-of-scope reject-fix changed FB to %s", st)
	}

	// Verify by filter naming both CVEs: only FA is resolved.
	status, body = h.do(h.memberA, false, http.MethodPost, "/api/v1/findings/actions/verify",
		map[string]any{"filter": map[string]any{"cve_ids": []string{h.cveA, h.cveB}}, "note": "ok"})
	if status != http.StatusOK || !strings.Contains(body, `"updated":1`) {
		t.Errorf("memberA verify by filter = %d %.200s, want updated 1", status, body)
	}
	if st, _, _ := h.findingState(h.findingB); st != "fix_applied" {
		t.Errorf("out-of-scope verify changed FB to %s", st)
	}
	if st, _, _ := h.findingState(h.findingA); st != "resolved" {
		t.Errorf("in-scope verify left FA %s, want resolved", st)
	}

	// The owner still verifies group B.
	status, body = h.do(h.owner, true, http.MethodPost, "/api/v1/findings/actions/verify",
		map[string]any{"filter": map[string]any{"cve_ids": []string{h.cveB}}, "note": "ok"})
	if status != http.StatusOK || !strings.Contains(body, `"updated":1`) {
		t.Errorf("owner verify B by filter = %d %.200s, want updated 1", status, body)
	}
	if st, _, _ := h.findingState(h.findingB); st != "resolved" {
		t.Errorf("owner verify left FB %s, want resolved", st)
	}
}
