package routes

// Groups that fill themselves, end to end over a migrated database: the
// service, the rule store and the data-scope enforcer with real repositories,
// across two tenants and members with different data scopes.

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type sgCtxKey struct{}

type sgCaller struct {
	id    shared.ID
	admin bool
	owner bool
}

type sgHarness struct {
	t   *testing.T
	db  *sql.DB
	svc *asset.AssetGroupService

	tenantA, tenantB           shared.ID
	admin, scoped, outsider    shared.ID // admin and scoped belong to A, outsider to B
	groupA, groupB             shared.ID
	visible1, visible2, hidden shared.ID
}

func (h *sgHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %q: %v", q, err)
	}
}

func (h *sgHarness) as(c sgCaller) context.Context {
	return context.WithValue(context.Background(), sgCtxKey{}, c)
}

func (h *sgHarness) newAsset(tenant shared.ID, name string) shared.ID {
	h.t.Helper()
	id := shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'domain')`, id.String(), tenant.String(), name)
	return id
}

func newSGHarness(t *testing.T) *sgHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping smart asset group DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	h := &sgHarness{t: t, db: sqldb}
	h.tenantA, h.tenantB = shared.NewID(), shared.NewID()
	h.admin, h.scoped, h.outsider = shared.NewID(), shared.NewID(), shared.NewID()
	for _, tn := range []shared.ID{h.tenantA, h.tenantB} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tn.String(), "sg-"+tn.String())
	}
	for _, u := range []shared.ID{h.admin, h.scoped, h.outsider} {
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'sg')`, u.String(), u.String()+"@sg.test")
	}
	t.Cleanup(func() {
		ctx := context.Background()
		for _, tn := range []shared.ID{h.tenantA, h.tenantB} {
			_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tn.String())
		}
		for _, u := range []shared.ID{h.admin, h.scoped, h.outsider} {
			_, _ = sqldb.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u.String())
		}
	})
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'admin')`, h.admin.String(), h.tenantA.String())
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, h.scoped.String(), h.tenantA.String())
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'admin')`, h.outsider.String(), h.tenantB.String())

	h.visible1 = h.newAsset(h.tenantA, "www.pti.com.vn")
	h.visible2 = h.newAsset(h.tenantA, "api.pti.com.vn")
	h.hidden = h.newAsset(h.tenantA, "vault.pti.com.vn")
	for _, a := range []shared.ID{h.visible1, h.visible2} {
		h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
			h.scoped.String(), h.tenantA.String(), a.String())
	}
	h.groupA, h.groupB = shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'sg-a')`, h.groupA.String(), h.tenantA.String())
	h.exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'sg-b')`, h.groupB.String(), h.tenantB.String())

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	enforcer := datascope.New(postgres.NewDataScopeRepository(db), func(ctx context.Context) datascope.Caller {
		c, _ := ctx.Value(sgCtxKey{}).(sgCaller)
		uid := ""
		if !c.id.IsZero() {
			uid = c.id.String()
		}
		return datascope.Caller{UserID: uid, IsAdmin: c.admin, IsOwner: c.owner}
	}, log)
	enforcer.SetAdminLookup(func(_ context.Context, _, user shared.ID) (bool, error) { return user == h.admin, nil })
	repo := postgres.NewAssetGroupRepository(db)
	h.svc = asset.NewAssetGroupService(repo, log)
	h.svc.SetDataScope(enforcer)
	h.svc.SetRuleStore(repo, postgres.NewAssetRepository(db))
	return h
}

func (h *sgHarness) rule(doc string) []byte { return []byte(doc) }

const ptiRule = `{"v":1,"domains":[{"name":"*.pti.com.vn"}]}`

func (h *sgHarness) memberIDs(group shared.ID) []shared.ID {
	h.t.Helper()
	rows, err := h.db.Query(`SELECT asset_id::text FROM asset_group_members WHERE asset_group_id = $1`, group.String())
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		id, _ := shared.IDFromString(s)
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		h.t.Fatal(err)
	}
	return out
}

func sameIDs(a []shared.ID, b ...shared.ID) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range b {
		if !slices.Contains(a, x) {
			return false
		}
	}
	return true
}

func TestSmartGroup_RuleStaysInsideTheEditorsDataScope(t *testing.T) {
	h := newSGHarness(t)
	admin, scoped := sgCaller{id: h.admin, admin: true}, sgCaller{id: h.scoped}

	// The same rule previews differently for two people: each sees their own scope.
	pa, err := h.svc.PreviewGroupRule(h.as(admin), h.tenantA.String(), nil, h.rule(ptiRule))
	if err != nil || pa.Count != 3 {
		t.Fatalf("admin preview: %+v %v", pa, err)
	}
	ps, err := h.svc.PreviewGroupRule(h.as(scoped), h.tenantA.String(), nil, h.rule(ptiRule))
	if err != nil || ps.Count != 2 {
		t.Fatalf("scoped preview: %+v %v", ps, err)
	}
	for _, s := range ps.Sample {
		if strings.Contains(s.Name, "vault") {
			t.Fatalf("the preview named an asset outside the caller's scope: %+v", ps.Sample)
		}
	}

	// A scoped editor's group never gets the hidden asset, now or on any later run.
	if _, err := h.svc.ChangeGroupRule(h.as(scoped), h.tenantA.String(), h.groupA, h.rule(ptiRule)); err != nil {
		t.Fatal(err)
	}
	if got := h.memberIDs(h.groupA); !sameIDs(got, h.visible1, h.visible2) {
		t.Fatalf("members of a scoped editor's group: %v", got)
	}
	newHidden := h.newAsset(h.tenantA, "new-hidden.pti.com.vn")
	if _, err := h.svc.EvaluateGroup(context.Background(), h.tenantA, h.groupA); err != nil {
		t.Fatal(err)
	}
	if got := h.memberIDs(h.groupA); slices.Contains(got, h.hidden) || slices.Contains(got, newHidden) || len(got) != 2 {
		t.Fatalf("background evaluation widened a scoped editor's group: %v", got)
	}

	// The editor gets access to the new asset: the next evaluation brings it in.
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.scoped.String(), h.tenantA.String(), newHidden.String())
	if _, err := h.svc.EvaluateGroup(context.Background(), h.tenantA, h.groupA); err != nil {
		t.Fatal(err)
	}
	if got := h.memberIDs(h.groupA); !sameIDs(got, h.visible1, h.visible2, newHidden) {
		t.Fatalf("members after the editor gained access: %v", got)
	}
}

func TestSmartGroup_RuleDoesNotCrossTenants(t *testing.T) {
	h := newSGHarness(t)
	foreign := h.newAsset(h.tenantB, "www.pti.com.vn.b.example") // not matching, but in B
	foreignMatch := h.newAsset(h.tenantB, "mail.pti.com.vn")     // matches the rule text, belongs to B
	_ = foreign
	admin := sgCaller{id: h.admin, admin: true}

	if _, err := h.svc.ChangeGroupRule(h.as(admin), h.tenantA.String(), h.groupA, h.rule(ptiRule)); err != nil {
		t.Fatal(err)
	}
	if got := h.memberIDs(h.groupA); slices.Contains(got, foreignMatch) {
		t.Fatalf("another tenant's asset joined: %v", got)
	}

	// Tenant B cannot read, preview against, set or paste into A's group.
	out := sgCaller{id: h.outsider, admin: true}
	if _, err := h.svc.GetGroupRule(h.as(out), h.tenantB.String(), h.groupA); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("GetGroupRule across tenants: %v", err)
	}
	if _, err := h.svc.ChangeGroupRule(h.as(out), h.tenantB.String(), h.groupA, h.rule(ptiRule)); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("ChangeGroupRule across tenants: %v", err)
	}
	if _, err := h.svc.PreviewGroupRule(h.as(out), h.tenantB.String(), &h.groupA, h.rule(ptiRule)); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("PreviewGroupRule across tenants: %v", err)
	}
	if _, err := h.svc.PasteToGroup(h.as(out), h.tenantB.String(), h.groupA, "www.pti.com.vn\n", asset.PasteOptions{}); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("PasteToGroup across tenants: %v", err)
	}
	if _, _, _, err := h.svc.AddMatchingToGroup(h.as(out), h.tenantB.String(), h.groupA, h.rule(ptiRule)); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("AddMatchingToGroup across tenants: %v", err)
	}
	if _, err := h.svc.ListGroupHistory(h.as(out), h.tenantB.String(), h.groupA, 1, 20); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("ListGroupHistory across tenants: %v", err)
	}
	if _, err := h.svc.ListAssetGroupHistory(h.as(out), h.tenantB.String(), h.visible1, 1, 20); err == nil {
		t.Error("ListAssetGroupHistory read the history of another tenant's asset")
	}
	// A paste in tenant B naming A's asset matches nothing there.
	res, err := h.svc.PasteToGroup(h.as(out), h.tenantB.String(), h.groupB, "www.pti.com.vn\n", asset.PasteOptions{})
	if err != nil || res.Matched != 0 || res.Added != 0 || res.NotFound != 1 {
		t.Fatalf("paste of another tenant's name: %+v %v", res, err)
	}
}

func TestSmartGroup_NewAssetJoinsAfterTheDebounce(t *testing.T) {
	h := newSGHarness(t)
	admin := sgCaller{id: h.admin, admin: true}
	if _, err := h.svc.ChangeGroupRule(h.as(admin), h.tenantA.String(), h.groupA, h.rule(ptiRule)); err != nil {
		t.Fatal(err)
	}
	sched := asset.NewGroupRuleScheduler(h.svc, 20*time.Millisecond, logger.NewNop())
	added := h.newAsset(h.tenantA, "new.pti.com.vn")
	h.newAsset(h.tenantA, "unrelated.example.org")
	// A burst of notifications is one run.
	for i := 0; i < 20; i++ {
		sched.NotifyAssetsChanged(h.tenantA)
	}
	sched.Wait()
	if got := h.memberIDs(h.groupA); !slices.Contains(got, added) || len(got) != 4 {
		t.Fatalf("members after a new asset: %v", got)
	}
	var joins int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM asset_group_member_history WHERE asset_group_id = $1 AND asset_id = $2 AND action = 'joined' AND reason = 'matches_rule'`,
		h.groupA.String(), added.String()).Scan(&joins)
	if joins != 1 {
		t.Fatalf("history rows for the new asset: %d", joins)
	}
}

func TestSmartGroup_ExcludesWinAndManualMembersStay(t *testing.T) {
	h := newSGHarness(t)
	admin := sgCaller{id: h.admin, admin: true}
	manual := h.newAsset(h.tenantA, "legacy.example.org")
	if _, err := h.svc.ChangeGroupRule(h.as(admin), h.tenantA.String(), h.groupA, h.rule(ptiRule)); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.AddAssetsToGroup(h.as(admin), h.tenantA.String(), h.groupA, []string{manual.String()}); err != nil {
		t.Fatal(err)
	}
	// Taking a rule member out keeps it out.
	if err := h.svc.RemoveAssetsFromGroup(h.as(admin), h.tenantA.String(), h.groupA, []string{h.hidden.String()}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := h.svc.EvaluateGroup(context.Background(), h.tenantA, h.groupA); err != nil {
			t.Fatal(err)
		}
	}
	got := h.memberIDs(h.groupA)
	if slices.Contains(got, h.hidden) || !slices.Contains(got, manual) || len(got) != 3 {
		t.Fatalf("members: %v", got)
	}
	// The preview agrees: the excluded asset is not counted.
	p, err := h.svc.PreviewGroupRule(h.as(admin), h.tenantA.String(), &h.groupA, h.rule(ptiRule))
	if err != nil || p.Count != 2 || p.WouldJoin != 0 || p.WouldLeave != 0 {
		t.Fatalf("preview of an up-to-date group: %+v %v", p, err)
	}
	// A rule change that stops matching removes the rule members and keeps the manual one.
	if _, err := h.svc.ChangeGroupRule(h.as(admin), h.tenantA.String(), h.groupA, h.rule(`{"v":1,"domains":[{"name":"www.pti.com.vn"}]}`)); err != nil {
		t.Fatal(err)
	}
	if got := h.memberIDs(h.groupA); !sameIDs(got, h.visible1, manual) {
		t.Fatalf("members after narrowing the rule: %v", got)
	}
	// Removing the rule keeps everything as plain members.
	if _, err := h.svc.ChangeGroupRule(h.as(admin), h.tenantA.String(), h.groupA, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.EvaluateGroup(context.Background(), h.tenantA, h.groupA); err != nil {
		t.Fatal(err)
	}
	if got := h.memberIDs(h.groupA); !sameIDs(got, h.visible1, manual) {
		t.Fatalf("members after removing the rule: %v", got)
	}
}

func TestSmartGroup_MemberCap(t *testing.T) {
	h := newSGHarness(t)
	admin := sgCaller{id: h.admin, admin: true}
	h.svc.OverrideMemberCap(2)

	p, err := h.svc.PreviewGroupRule(h.as(admin), h.tenantA.String(), nil, h.rule(ptiRule))
	if err != nil || !p.OverCap || p.Cap != 2 || p.Count != 3 {
		t.Fatalf("preview over the cap: %+v %v", p, err)
	}
	if _, err := h.svc.ChangeGroupRule(h.as(admin), h.tenantA.String(), h.groupA, h.rule(ptiRule)); err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a rule over the cap was accepted: %v", err)
	}
	if got := h.memberIDs(h.groupA); len(got) != 0 {
		t.Fatalf("a refused rule changed the group: %v", got)
	}

	// A group already filled that grows past the cap later keeps its members
	// and reports the state.
	h.svc.OverrideMemberCap(0)
	if _, err := h.svc.ChangeGroupRule(h.as(admin), h.tenantA.String(), h.groupA, h.rule(ptiRule)); err != nil {
		t.Fatal(err)
	}
	h.svc.OverrideMemberCap(2)
	res, err := h.svc.EvaluateGroup(context.Background(), h.tenantA, h.groupA)
	if err != nil || !res.OverCap {
		t.Fatalf("evaluation over the cap: %+v %v", res, err)
	}
	if got := h.memberIDs(h.groupA); len(got) != 3 {
		t.Fatalf("an over-cap evaluation changed the members: %v", got)
	}
	st, err := h.svc.GetGroupRule(h.as(admin), h.tenantA.String(), h.groupA)
	if err != nil || st.Status != assetgroup.RuleStatusOverCap {
		t.Fatalf("rule state: %+v %v", st, err)
	}

	// Manual adds are capped too: "add all matching" past the cap is refused.
	if _, _, _, err := h.svc.AddMatchingToGroup(h.as(admin), h.tenantA.String(), h.groupB, h.rule(ptiRule)); err == nil {
		t.Fatal("add matching past the cap was accepted (and group B is another tenant's)")
	}
}

func TestSmartGroup_EditorWhoLeftPausesTheRule(t *testing.T) {
	h := newSGHarness(t)
	scoped := sgCaller{id: h.scoped}
	if _, err := h.svc.ChangeGroupRule(h.as(scoped), h.tenantA.String(), h.groupA, h.rule(ptiRule)); err != nil {
		t.Fatal(err)
	}
	h.exec(`UPDATE tenant_members SET status = 'offboarded' WHERE user_id = $1 AND tenant_id = $2`, h.scoped.String(), h.tenantA.String())
	h.newAsset(h.tenantA, "later.pti.com.vn")
	if _, err := h.svc.EvaluateGroup(context.Background(), h.tenantA, h.groupA); err != nil {
		t.Fatal(err)
	}
	if got := h.memberIDs(h.groupA); !sameIDs(got, h.visible1, h.visible2) {
		t.Fatalf("a rule whose editor left changed the members: %v", got)
	}
	st, err := h.svc.GetGroupRule(h.as(sgCaller{id: h.admin, admin: true}), h.tenantA.String(), h.groupA)
	if err != nil || st.Status != assetgroup.RuleStatusPaused {
		t.Fatalf("rule state: %+v %v", st, err)
	}
}

func TestSmartGroup_RuleIsValidatedLikeTheAssetsList(t *testing.T) {
	h := newSGHarness(t)
	admin := sgCaller{id: h.admin, admin: true}
	for name, doc := range map[string]string{
		"unknown asset type": `{"v":1,"filter":{"types":["not-a-type"]}}`,
		"bad status":         `{"v":1,"filter":{"statuses":["gone"]}}`,
		"too many tags":      `{"v":1,"filter":{"tags":["` + strings.Repeat(`a","`, 25) + `a"]}}`,
		"bad risk":           `{"v":1,"filter":{"min_risk_score":101}}`,
		"unknown key":        `{"v":1,"filter":{"sort":"name"}}`,
		"not a domain":       `{"v":1,"domains":[{"name":"x/../y"}]}`,
	} {
		if _, err := h.svc.PreviewGroupRule(h.as(admin), h.tenantA.String(), nil, h.rule(doc)); err == nil || !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A filter-only rule works and is the Assets list filter.
	p, err := h.svc.PreviewGroupRule(h.as(admin), h.tenantA.String(), nil, h.rule(`{"v":1,"filter":{"types":["domain"],"search":"vault"}}`))
	if err != nil || p.Count != 1 {
		t.Fatalf("filter rule preview: %+v %v", p, err)
	}
	// An API key has no editor to evaluate as.
	if _, err := h.svc.ChangeGroupRule(context.Background(), h.tenantA.String(), h.groupA, h.rule(ptiRule)); err == nil {
		t.Fatal("a rule was set without a signed-in editor")
	}
}

func TestSmartGroup_IncludeRelatedStaysInScope(t *testing.T) {
	h := newSGHarness(t)
	svcA := shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, parent_id) VALUES ($1, $2, 'www.pti.com.vn:443', 'service', $3)`,
		svcA.String(), h.tenantA.String(), h.visible1.String())
	svcHidden := shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, parent_id) VALUES ($1, $2, 'api.pti.com.vn:8443', 'service', $3)`,
		svcHidden.String(), h.tenantA.String(), h.visible2.String())
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.scoped.String(), h.tenantA.String(), svcA.String())
	doc := `{"v":1,"domains":[{"name":"pti.com.vn","subdomains":true}],"include_related":true}`

	ps, err := h.svc.PreviewGroupRule(h.as(sgCaller{id: h.scoped}), h.tenantA.String(), nil, h.rule(doc))
	if err != nil || ps.Count != 3 { // two hosts and the one service they may see
		t.Fatalf("scoped preview with related: %+v %v", ps, err)
	}
	pa, err := h.svc.PreviewGroupRule(h.as(sgCaller{id: h.admin, admin: true}), h.tenantA.String(), nil, h.rule(doc))
	if err != nil || pa.Count != 5 {
		t.Fatalf("admin preview with related: %+v %v", pa, err)
	}
	_ = assetdom.AssetTypeDomain
}

type sgFakeGuard struct {
	privileged bool
	stepUp     error
	calls      int
}

func (g *sgFakeGuard) FlagPrivileged(_ context.Context, _ shared.ID, teams []assetgroup.Use) ([]assetgroup.Use, error) {
	out := slices.Clone(teams)
	for i := range out {
		out[i].Privileged = g.privileged
	}
	return out, nil
}

func (g *sgFakeGuard) RequireOwnerStepUp(context.Context, shared.ID, string) error {
	g.calls++
	return g.stepUp
}

func TestSmartGroup_ImpactAndPrivilegedTeams(t *testing.T) {
	h := newSGHarness(t)
	admin := sgCaller{id: h.admin, admin: true}
	// A team's scope rule and a scan use the group.
	team := shared.NewID()
	h.exec(`INSERT INTO groups (id, tenant_id, name, slug, group_type) VALUES ($1, $2, 'Payments', $3, 'team')`,
		team.String(), h.tenantA.String(), "pay-"+team.String())
	h.exec(`INSERT INTO group_asset_scope_rules (tenant_id, group_id, name, rule_type, match_asset_group_ids) VALUES ($1, $2, 'r', 'asset_group_match', ARRAY[$3]::uuid[])`,
		h.tenantA.String(), team.String(), h.groupA.String())
	h.exec(`INSERT INTO scans (id, tenant_id, name, asset_group_id, scan_type, scanner_name) VALUES ($1, $2, 'nightly', $3, 'single', 'nuclei')`,
		shared.NewID().String(), h.tenantA.String(), h.groupA.String())

	guard := &sgFakeGuard{}
	h.svc.SetAccessGuard(guard)

	p, err := h.svc.PreviewGroupRule(h.as(admin), h.tenantA.String(), &h.groupA, h.rule(ptiRule))
	if err != nil || p.Impact == nil || !p.Impact.Widens || p.WouldJoin != 3 ||
		len(p.Impact.Teams) != 1 || p.Impact.Teams[0].Name != "Payments" || len(p.Impact.Scans) != 1 || p.Impact.Scans[0].Name != "nightly" {
		t.Fatalf("preview impact: %+v %v", p, err)
	}
	ch, err := h.svc.ChangeGroupRule(h.as(admin), h.tenantA.String(), h.groupA, h.rule(ptiRule))
	if err != nil || !ch.Impact.Widens || ch.Impact.Privilege || guard.calls != 0 {
		t.Fatalf("widening set: %+v %v (step-up calls %d)", ch, err, guard.calls)
	}
	// Re-setting the same rule widens nothing.
	if ch, err = h.svc.ChangeGroupRule(h.as(admin), h.tenantA.String(), h.groupA, h.rule(ptiRule)); err != nil || ch.Impact.Widens {
		t.Fatalf("a no-op set widened: %+v %v", ch, err)
	}

	// A privileged team: every change goes through the owner and step-up check.
	guard.privileged = true
	guard.stepUp = errors.New("owner only")
	if _, err := h.svc.ChangeGroupRule(h.as(admin), h.tenantA.String(), h.groupA, h.rule(`{"v":1,"domains":[{"name":"www.pti.com.vn"}]}`)); err == nil || err.Error() != "owner only" {
		t.Fatalf("rule change of a privileged team's group: %v", err)
	}
	if err := h.svc.AddAssetsToGroup(h.as(admin), h.tenantA.String(), h.groupA, []string{h.newAsset(h.tenantA, "x.example.org").String()}); err == nil {
		t.Fatal("members of a privileged team's group changed without the owner check")
	}
	if err := h.svc.RemoveAssetsFromGroup(h.as(admin), h.tenantA.String(), h.groupA, []string{h.visible1.String()}); err == nil {
		t.Fatal("members of a privileged team's group removed without the owner check")
	}
	if _, err := h.svc.PasteToGroup(h.as(admin), h.tenantA.String(), h.groupA, "www.pti.com.vn\n", asset.PasteOptions{}); err == nil {
		t.Fatal("paste into a privileged team's group without the owner check")
	}
	if got := h.memberIDs(h.groupA); len(got) != 3 {
		t.Fatalf("a refused change altered the members: %v", got)
	}
	// A dry-run paste changes nothing and needs no step-up.
	if _, err := h.svc.PasteToGroup(h.as(admin), h.tenantA.String(), h.groupA, "www.pti.com.vn\n", asset.PasteOptions{DryRun: true}); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	// With the check passing, the change goes through and says the team is privileged.
	guard.stepUp = nil
	ch, err = h.svc.ChangeGroupRule(h.as(admin), h.tenantA.String(), h.groupA, h.rule(`{"v":1,"domains":[{"name":"www.pti.com.vn"}]}`))
	if err != nil || ch.Impact.Privilege != true {
		t.Fatalf("owner change: %+v %v", ch, err)
	}
}

type sgPasteWorld struct {
	mu      sync.Mutex
	created []string
	held    []string
	h       *sgHarness
}

func (w *sgPasteWorld) paste() asset.PasteAssets {
	return asset.PasteAssets{
		Create: func(_ context.Context, in asset.CreateAssetInput) (*assetdom.Asset, error) {
			var exists bool
			_ = w.h.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM assets WHERE tenant_id = $1 AND name = $2)`, in.TenantID, in.Name).Scan(&exists)
			if exists {
				return nil, &asset.DuplicateAssetError{}
			}
			typ, _ := assetdom.ParseAssetType(in.Type)
			a, err := assetdom.NewAssetWithSubType(in.Name, typ, "", assetdom.CriticalityMedium)
			if err != nil {
				return nil, err
			}
			tid, _ := shared.IDFromString(in.TenantID)
			w.h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, $4)`, a.ID().String(), tid.String(), in.Name, in.Type)
			w.mu.Lock()
			w.created = append(w.created, in.Name)
			w.mu.Unlock()
			return a, nil
		},
		Covered: func(_ context.Context, _ shared.ID, names []string) (map[string]bool, error) {
			out := map[string]bool{}
			for _, n := range names {
				if strings.HasSuffix(n, ".pti.com.vn") {
					out[n] = true
				}
			}
			return out, nil
		},
		HoldCandidates: func(_ context.Context, _ shared.ID, created []asset.CreatedPasteAsset) error {
			w.mu.Lock()
			defer w.mu.Unlock()
			for _, c := range created {
				w.held = append(w.held, c.Name)
			}
			return nil
		},
	}
}

func TestSmartGroup_PasteMatchesValidatesAndCreatesThroughTheScopeCheck(t *testing.T) {
	h := newSGHarness(t)
	admin := sgCaller{id: h.admin, admin: true}
	world := &sgPasteWorld{h: h}
	h.svc.SetPasteAssets(world.paste())
	ip := h.newAsset(h.tenantA, "10.0.0.7")
	h.exec(`UPDATE assets SET asset_type = 'ip_address' WHERE id = $1`, ip.String())

	text := strings.Join([]string{
		"# my list",
		"WWW.PTI.COM.VN",          // existing
		"api.pti.com.vn.",         // existing, trailing dot
		"new.pti.com.vn",          // missing, in scope
		"stranger.example.net",    // missing, outside scope
		"10.0.0.7",                // existing address
		"javascript:alert(1)",     // rejected
		"ftp://files.pti.com.vn",  // rejected
		"www.pti.com.vn\rEvil: 1", // rejected (control character)
		"10.0.0.0/7",              // rejected (too broad)
		"192.0.2.0/24",            // range without assets: not found, never created
	}, "\n")

	// A dry run reports and changes nothing.
	dry, err := h.svc.PasteToGroup(h.as(admin), h.tenantA.String(), h.groupA, text, asset.PasteOptions{DryRun: true, CreateMissing: true})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Matched != 3 || dry.NotFound != 3 || len(dry.Rejected) != 4 || dry.Added != 0 || len(world.created) != 0 || len(h.memberIDs(h.groupA)) != 0 {
		t.Fatalf("dry run: %+v created=%v", dry, world.created)
	}

	// Without create-missing only the existing assets are added.
	res, err := h.svc.PasteToGroup(h.as(admin), h.tenantA.String(), h.groupA, text, asset.PasteOptions{})
	if err != nil || res.Added != 3 || res.Created != 0 || len(world.created) != 0 {
		t.Fatalf("paste: %+v %v", res, err)
	}
	var src string
	_ = h.db.QueryRow(`SELECT source FROM asset_group_members WHERE asset_group_id = $1 AND asset_id = $2`, h.groupA.String(), h.visible1.String()).Scan(&src)
	if src != assetgroup.SourcePaste {
		t.Fatalf("member source %q, want paste", src)
	}

	// With create-missing the in-scope name joins the inventory, the other is
	// held as a candidate; both become members, the range is never created.
	res, err = h.svc.PasteToGroup(h.as(admin), h.tenantA.String(), h.groupA, text, asset.PasteOptions{CreateMissing: true})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(world.created)
	if !slices.Equal(world.created, []string{"new.pti.com.vn", "stranger.example.net"}) ||
		!slices.Equal(world.held, []string{"stranger.example.net"}) || res.Created != 2 || res.Outside != 1 {
		t.Fatalf("created=%v held=%v res=%+v", world.created, world.held, res)
	}
	if len(h.memberIDs(h.groupA)) != 5 {
		t.Fatalf("members: %v", h.memberIDs(h.groupA))
	}

	// A scoped member cannot learn that an asset outside their scope exists:
	// it counts as missing, and creating it is skipped as a duplicate.
	world2 := &sgPasteWorld{h: h}
	h.svc.SetPasteAssets(world2.paste())
	sres, err := h.svc.PasteToGroup(h.as(sgCaller{id: h.scoped}), h.tenantA.String(), h.groupA, "vault.pti.com.vn\nwww.pti.com.vn\n", asset.PasteOptions{CreateMissing: true})
	if err != nil || sres.Matched != 1 || sres.Skipped != 1 || sres.Created != 0 || len(world2.created) != 0 {
		t.Fatalf("scoped paste: %+v %v", sres, err)
	}

	// Size and shape limits.
	big := strings.Repeat("a.pti.com.vn\n", assetgroup.MaxPasteLines+1)
	if _, err := h.svc.PasteToGroup(h.as(admin), h.tenantA.String(), h.groupA, big, asset.PasteOptions{}); err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an oversized paste was accepted: %v", err)
	}
	var many strings.Builder
	for i := 0; i < assetgroup.MaxPasteCreate+1; i++ {
		many.WriteString("m" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i/676)) + ".pti.com.vn\n")
	}
	if _, err := h.svc.PasteToGroup(h.as(admin), h.tenantA.String(), h.groupA, many.String(), asset.PasteOptions{CreateMissing: true}); err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("creating more than the limit was accepted: %v", err)
	}
}

func TestSmartGroup_AddMatchingIsNotLimitedToAPage(t *testing.T) {
	h := newSGHarness(t)
	admin := sgCaller{id: h.admin, admin: true}
	for i := 0; i < 130; i++ { // more than the 100 of one list page
		h.newAsset(h.tenantA, "bulk"+strings.Repeat("0", i%3)+string(rune('a'+i%26))+string(rune('a'+i/26))+".bulk.example.com")
	}
	added, matched, impact, err := h.svc.AddMatchingToGroup(h.as(admin), h.tenantA.String(), h.groupA,
		h.rule(`{"v":1,"domains":[{"name":"bulk.example.com","subdomains":true}]}`))
	if err != nil || added != 130 || matched != 130 || impact == nil {
		t.Fatalf("add matching: %d/%d %v", added, matched, err)
	}
	var manual int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM asset_group_members WHERE asset_group_id = $1 AND source = 'manual'`, h.groupA.String()).Scan(&manual)
	if manual != 130 {
		t.Fatalf("manual members: %d", manual)
	}
	// A restricted caller sees only the history of the assets in their scope
	// (the group is visible to them once one of its members is).
	if err := h.svc.AddAssetsToGroup(h.as(admin), h.tenantA.String(), h.groupA, []string{h.visible1.String()}); err != nil {
		t.Fatal(err)
	}
	hist, err := h.svc.ListGroupHistory(h.as(sgCaller{id: h.scoped}), h.tenantA.String(), h.groupA, 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist.Data) != 1 || hist.Data[0].AssetID != h.visible1 {
		t.Fatalf("history of a scoped reader: %+v", hist.Data)
	}
}
