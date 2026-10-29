package postgres

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The rule store of asset groups against a migrated database: the domain
// predicate on a label boundary, the evaluation written as rule members (with
// manual members kept and excludes winning), the cap, history, and tenant
// isolation of every statement.

type ruleFixture struct {
	t      *testing.T
	ctx    context.Context
	db     *sql.DB
	repo   *AssetGroupRepository
	assets *AssetRepository
	tenant shared.ID
	group  shared.ID
}

func newRuleFixture(t *testing.T) *ruleFixture {
	t.Helper()
	db, ctx := openRegistryDB(t)
	f := &ruleFixture{t: t, ctx: ctx, db: db, repo: NewAssetGroupRepository(&DB{DB: db}), assets: NewAssetRepository(&DB{DB: db})}
	f.tenant = seedTestTenant(ctx, t, db)
	f.group = f.newGroup(f.tenant, "rule-"+shared.NewID().String())
	return f
}

func (f *ruleFixture) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.db.ExecContext(f.ctx, q, args...); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
}

func (f *ruleFixture) newGroup(tenant shared.ID, name string) shared.ID {
	f.t.Helper()
	id := shared.NewID()
	f.exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, $3)`, id.String(), tenant.String(), name)
	return id
}

func (f *ruleFixture) newAsset(tenant shared.ID, name string) shared.ID {
	f.t.Helper()
	id := shared.NewID()
	f.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'domain')`, id.String(), tenant.String(), name)
	return id
}

func (f *ruleFixture) members(group shared.ID) map[shared.ID]string {
	f.t.Helper()
	rows, err := f.db.QueryContext(f.ctx, `SELECT asset_id::text, source FROM asset_group_members WHERE asset_group_id = $1`, group.String())
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	out := map[shared.ID]string{}
	for rows.Next() {
		var id, src string
		if err := rows.Scan(&id, &src); err != nil {
			f.t.Fatal(err)
		}
		sid, _ := shared.IDFromString(id)
		out[sid] = src
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *ruleFixture) tenantFilter(extra func(*asset.Filter)) asset.Filter {
	tid := f.tenant.String()
	flt := asset.NewFilter()
	flt.TenantID = &tid
	if extra != nil {
		extra(&flt)
	}
	return flt
}

func TestDomainNamesFilter_LabelBoundary_DB(t *testing.T) {
	f := newRuleFixture(t)
	apex := f.newAsset(f.tenant, "example.com")
	sub := f.newAsset(f.tenant, "www.example.com")
	deep := f.newAsset(f.tenant, "a.b.example.com")
	lookalike := f.newAsset(f.tenant, "evilexample.com")
	dashed := f.newAsset(f.tenant, "evil-example.com")
	suffixed := f.newAsset(f.tenant, "example.com.evil.com")
	other := f.newAsset(f.tenant, "other.com.vn")
	// A wildcard character in a stored name must not widen the match.
	percent := f.newAsset(f.tenant, "x%.example.com")
	foreign := f.newAsset(seedTestTenant(f.ctx, t, f.db), "foreign.example.com")

	ids := func(conds ...asset.DomainName) []shared.ID {
		t.Helper()
		got, err := f.assets.MatchingIDs(f.ctx, f.tenantFilter(func(fl *asset.Filter) { fl.DomainNames = conds }), "", 100)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	has := func(got []shared.ID, want ...shared.ID) bool {
		if len(got) != len(want) {
			return false
		}
		for _, w := range want {
			if !slices.Contains(got, w) {
				return false
			}
		}
		return true
	}
	if got := ids(asset.DomainName{Name: "example.com", Subdomains: true}); !has(got, apex, sub, deep, percent) {
		t.Errorf("with subdomains matched %v, want the apex and the names below it only", got)
	}
	if got := ids(asset.DomainName{Name: "example.com"}); !has(got, apex) {
		t.Errorf("exact matched %v, want the apex only", got)
	}
	for _, bad := range []shared.ID{lookalike, dashed, suffixed, other, foreign} {
		if slices.Contains(ids(asset.DomainName{Name: "example.com", Subdomains: true}), bad) {
			t.Errorf("asset %s matched outside the label boundary or the tenant", bad)
		}
	}
	// Two conditions are an OR.
	if got := ids(asset.DomainName{Name: "example.com"}, asset.DomainName{Name: "other.com.vn"}); !has(got, apex, other) {
		t.Errorf("or of two conditions matched %v", got)
	}
	// A LIKE metacharacter in the condition matches nothing extra.
	if got := ids(asset.DomainName{Name: "%.vn", Subdomains: true}); len(got) != 0 {
		t.Errorf("a pattern character matched %v", got)
	}
}

func TestApplyRule_JoinLeaveManualAndExclusions_DB(t *testing.T) {
	f := newRuleFixture(t)
	a, b, c, d := f.newAsset(f.tenant, "a.example.com"), f.newAsset(f.tenant, "b.example.com"),
		f.newAsset(f.tenant, "c.example.com"), f.newAsset(f.tenant, "d.example.com")
	apply := func(ids ...shared.ID) assetgroup.ApplyResult {
		t.Helper()
		res, err := f.repo.ApplyRule(f.ctx, assetgroup.ApplyInput{TenantID: f.tenant, GroupID: f.group, AssetIDs: ids, Cap: 100})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	// A person adds d by hand; the rule matches a and b.
	if n, err := f.repo.AddMembers(f.ctx, f.tenant, f.group, []shared.ID{d}, assetgroup.SourceManual, nil); err != nil || n != 1 {
		t.Fatalf("add manual: %d %v", n, err)
	}
	if res := apply(a, b); res.Joined != 2 || res.Left != 0 {
		t.Fatalf("first evaluation: %+v", res)
	}
	m := f.members(f.group)
	if m[a] != "rule" || m[b] != "rule" || m[d] != "manual" || len(m) != 3 {
		t.Fatalf("members after first evaluation: %v", m)
	}

	// The rule now matches b and c: a leaves, c joins, the manual d stays.
	if res := apply(b, c); res.Joined != 1 || res.Left != 1 {
		t.Fatalf("second evaluation: %+v", res)
	}
	m = f.members(f.group)
	if _, ok := m[a]; ok || m[b] != "rule" || m[c] != "rule" || m[d] != "manual" {
		t.Fatalf("members after second evaluation: %v", m)
	}

	// A person takes b out: it stays out while the rule matches it.
	if n, err := f.repo.RemoveMembers(f.ctx, f.tenant, f.group, []shared.ID{b}, true, nil); err != nil || n != 1 {
		t.Fatalf("remove with exclusion: %d %v", n, err)
	}
	if res := apply(b, c); res.Joined != 0 {
		t.Fatalf("an excluded asset joined again: %+v", res)
	}
	if _, ok := f.members(f.group)[b]; ok {
		t.Fatal("excludes must win over the rule")
	}
	if ex, _ := f.repo.ExcludedIDs(f.ctx, f.tenant, f.group); len(ex) != 1 || ex[0] != b {
		t.Fatalf("exclusions: %v", ex)
	}

	// Adding it by hand again lifts the exclusion.
	if n, err := f.repo.AddMembers(f.ctx, f.tenant, f.group, []shared.ID{b}, assetgroup.SourceManual, nil); err != nil || n != 1 {
		t.Fatalf("re-add: %d %v", n, err)
	}
	if ex, _ := f.repo.ExcludedIDs(f.ctx, f.tenant, f.group); len(ex) != 0 {
		t.Fatalf("exclusion not lifted: %v", ex)
	}
	// A rule member added by hand becomes a manual member that survives the rule.
	if n, err := f.repo.AddMembers(f.ctx, f.tenant, f.group, []shared.ID{c}, assetgroup.SourceManual, nil); err != nil || n != 0 {
		t.Fatalf("promote: %d %v", n, err)
	}
	apply() // the rule matches nothing now
	m = f.members(f.group)
	if m[b] != "manual" || m[c] != "manual" || m[d] != "manual" || len(m) != 3 {
		t.Fatalf("manual members must survive an empty result: %v", m)
	}

	// History: every join and leave was recorded with its reason.
	hist, err := f.repo.ListHistory(f.ctx, f.tenant, f.group, pagination.New(1, 50))
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]int{}
	for _, h := range hist.Data {
		reasons[h.Action+"/"+h.Reason]++
		if h.AssetName == "" {
			t.Errorf("history entry without an asset name: %+v", h)
		}
	}
	if reasons["joined/matches_rule"] != 3 || reasons["left/no_longer_matches"] != 1 ||
		reasons["joined/added_by_hand"] != 2 || reasons["left/removed_by_hand"] != 1 {
		t.Fatalf("history reasons: %v", reasons)
	}
	assetHist, err := f.repo.ListAssetHistory(f.ctx, f.tenant, b, pagination.New(1, 50))
	if err != nil || assetHist.Total < 3 {
		t.Fatalf("asset history: %+v %v", assetHist, err)
	}
	if assetHist.Data[0].GroupName == "" {
		t.Error("asset history lacks the group name")
	}
}

func TestApplyRule_CapRefusesAndChangesNothing_DB(t *testing.T) {
	f := newRuleFixture(t)
	var ids []shared.ID
	for _, n := range []string{"1", "2", "3", "4"} {
		ids = append(ids, f.newAsset(f.tenant, n+".cap.example.com"))
	}
	manual := f.newAsset(f.tenant, "manual.cap.example.com")
	if _, err := f.repo.AddMembers(f.ctx, f.tenant, f.group, []shared.ID{manual}, assetgroup.SourceManual, nil); err != nil {
		t.Fatal(err)
	}
	res, err := f.repo.ApplyRule(f.ctx, assetgroup.ApplyInput{TenantID: f.tenant, GroupID: f.group, AssetIDs: ids[:2], Cap: 3})
	if err != nil || res.OverCap || res.Joined != 2 {
		t.Fatalf("within the cap: %+v %v", res, err)
	}
	// Four matches plus the manual member is five: over the cap of three.
	res, err = f.repo.ApplyRule(f.ctx, assetgroup.ApplyInput{TenantID: f.tenant, GroupID: f.group, AssetIDs: ids, Cap: 3})
	if err != nil || !res.OverCap || res.Joined != 0 || res.Left != 0 {
		t.Fatalf("over the cap: %+v %v", res, err)
	}
	if got := f.members(f.group); len(got) != 3 {
		t.Fatalf("an over-cap result changed the members: %v", got)
	}
}

func TestRuleStore_CrossTenant_DB(t *testing.T) {
	f := newRuleFixture(t)
	other := seedTestTenant(f.ctx, t, f.db)
	otherGroup := f.newGroup(other, "other-"+shared.NewID().String())
	mine := f.newAsset(f.tenant, "mine.example.com")
	theirs := f.newAsset(other, "theirs.example.com")

	// A rule result naming another tenant's asset never writes it.
	res, err := f.repo.ApplyRule(f.ctx, assetgroup.ApplyInput{TenantID: f.tenant, GroupID: f.group, AssetIDs: []shared.ID{mine, theirs}, Cap: 10})
	if err != nil || res.Joined != 1 {
		t.Fatalf("apply: %+v %v", res, err)
	}
	if _, ok := f.members(f.group)[theirs]; ok {
		t.Fatal("another tenant's asset joined the group")
	}
	// Writing through another tenant's id as the tenant touches nothing.
	if _, err := f.repo.ApplyRule(f.ctx, assetgroup.ApplyInput{TenantID: other, GroupID: f.group, AssetIDs: []shared.ID{theirs}, Cap: 10}); err == nil {
		t.Fatal("applying a rule to another tenant's group must fail")
	}
	if n, _ := f.repo.AddMembers(f.ctx, other, f.group, []shared.ID{theirs}, assetgroup.SourceManual, nil); n != 0 {
		t.Fatal("added members to another tenant's group")
	}
	if n, _ := f.repo.AddMembers(f.ctx, f.tenant, f.group, []shared.ID{theirs}, assetgroup.SourceManual, nil); n != 0 {
		t.Fatal("added another tenant's asset")
	}
	if n, _ := f.repo.RemoveMembers(f.ctx, other, f.group, []shared.ID{mine}, true, nil); n != 0 {
		t.Fatal("removed members of another tenant's group")
	}
	if ex, _ := f.repo.ExcludedIDs(f.ctx, other, f.group); len(ex) != 0 {
		t.Fatal("excluded through another tenant")
	}
	if _, ok := f.members(f.group)[mine]; !ok {
		t.Fatal("the member was removed through another tenant")
	}
	if _, err := f.repo.GetRuleState(f.ctx, other, f.group); err == nil {
		t.Fatal("read another tenant's rule")
	}
	if err := f.repo.SetRule(f.ctx, other, f.group, &assetgroup.Rule{Version: 1, Filter: assetgroup.RuleFilter{Search: "x"}}, nil, nil); err == nil {
		t.Fatal("set a rule on another tenant's group")
	}
	if hist, _ := f.repo.ListHistory(f.ctx, other, f.group, pagination.New(1, 10)); hist.Total != 0 {
		t.Fatal("read another tenant's history")
	}
	_ = otherGroup
	if refs, _ := f.repo.ListRuleGroups(f.ctx, other); len(refs) != 0 {
		t.Fatal("listed rule groups of a tenant that has none")
	}
}

func TestSetRule_StateAndRelease_DB(t *testing.T) {
	f := newRuleFixture(t)
	a := f.newAsset(f.tenant, "a.rule.example.com")
	rule := &assetgroup.Rule{Version: 1, Domains: []assetgroup.DomainCondition{{Name: "rule.example.com", Subdomains: true}}}
	user := seedGroupsUser(f.ctx, t, f.db, "rule-editor.test")
	if err := f.repo.SetRule(f.ctx, f.tenant, f.group, rule, &user, &user); err != nil {
		t.Fatal(err)
	}
	st, err := f.repo.GetRuleState(f.ctx, f.tenant, f.group)
	if err != nil || st.Rule == nil || st.EditorID == nil || *st.EditorID != user || st.Status != assetgroup.RuleStatusIdle {
		t.Fatalf("state: %+v %v", st, err)
	}
	if refs, _ := f.repo.ListRuleGroups(f.ctx, f.tenant); len(refs) != 1 || refs[0].GroupID != f.group {
		t.Fatalf("rule groups: %+v", refs)
	}
	if _, err := f.repo.ApplyRule(f.ctx, assetgroup.ApplyInput{TenantID: f.tenant, GroupID: f.group, AssetIDs: []shared.ID{a}, Cap: 10}); err != nil {
		t.Fatal(err)
	}
	if st, _ = f.repo.GetRuleState(f.ctx, f.tenant, f.group); st.Status != assetgroup.RuleStatusOK || st.EvaluatedAt == nil {
		t.Fatalf("status after evaluation: %+v", st)
	}
	sums, err := f.repo.GetRuleSummaries(f.ctx, f.tenant, []shared.ID{f.group, shared.NewID()})
	if err != nil || len(sums) != 1 || sums[f.group].Rule == nil {
		t.Fatalf("summaries: %+v %v", sums, err)
	}
	// Removing the rule keeps the members, as plain members.
	if err := f.repo.SetRule(f.ctx, f.tenant, f.group, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if f.members(f.group)[a] != "manual" {
		t.Fatalf("members after the rule was removed: %v", f.members(f.group))
	}
	if st, _ = f.repo.GetRuleState(f.ctx, f.tenant, f.group); st.Rule != nil {
		t.Fatal("rule not cleared")
	}
	if active, err := f.repo.EditorActive(f.ctx, f.tenant, user); err != nil || active {
		t.Fatalf("a user outside the tenant is an active editor: %v %v", active, err)
	}
}

func TestRelatedAssetIDs_DB(t *testing.T) {
	f := newRuleFixture(t)
	host := f.newAsset(f.tenant, "host.related.example.com")
	svc, url, cert, unrelated := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	f.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, parent_id) VALUES ($1, $2, 'host.related.example.com:443', 'service', $3)`,
		svc.String(), f.tenant.String(), host.String())
	f.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'https://host.related.example.com/', 'application')`, url.String(), f.tenant.String())
	f.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'cert-1', 'certificate')`, cert.String(), f.tenant.String())
	f.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'unrelated.example.org:22', 'service')`, unrelated.String(), f.tenant.String())
	f.exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, 'runs_on')`,
		f.tenant.String(), url.String(), host.String())
	f.exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, 'serves_certificate')`,
		f.tenant.String(), host.String(), cert.String())
	got, err := f.repo.RelatedAssetIDs(f.ctx, f.tenant, []shared.ID{host})
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(got, func(a, b shared.ID) int { return strings.Compare(a.String(), b.String()) })
	want := []shared.ID{svc, url, cert}
	slices.SortFunc(want, func(a, b shared.ID) int { return strings.Compare(a.String(), b.String()) })
	if !slices.Equal(got, want) {
		t.Fatalf("related = %v, want %v", got, want)
	}
	if other, _ := f.repo.RelatedAssetIDs(f.ctx, seedTestTenant(f.ctx, t, f.db), []shared.ID{host}); len(other) != 0 {
		t.Fatalf("another tenant read related assets: %v", other)
	}
}

func TestUses_ScansAndTeams_DB(t *testing.T) {
	f := newRuleFixture(t)
	other := seedTestTenant(f.ctx, t, f.db)
	f.exec(`INSERT INTO scans (id, tenant_id, name, asset_group_ids, scan_type, scanner_name) VALUES ($1, $2, 'weekly', ARRAY[$3]::uuid[], 'single', 'nuclei')`,
		shared.NewID().String(), f.tenant.String(), f.group.String())
	uses, err := f.repo.ScanUses(f.ctx, f.tenant, f.group)
	if err != nil || len(uses) != 1 || uses[0].Name != "weekly" {
		t.Fatalf("scan uses: %+v %v", uses, err)
	}
	if uses, _ := f.repo.ScanUses(f.ctx, other, f.group); len(uses) != 0 {
		t.Fatalf("another tenant sees scan uses: %+v", uses)
	}
}
