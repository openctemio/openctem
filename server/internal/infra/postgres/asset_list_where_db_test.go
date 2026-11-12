package postgres

// The asset inventory on the list query contract: every registry field runs
// (as the list, and rebased onto the bare table as the search box reads
// it), every old GET /assets param selects the same assets through the
// registry as through the old Filter, another tenant's assets never match,
// and the count stops at asset.CountCap.

import (
	"context"
	"database/sql"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/assetlist"
	"github.com/openctemio/openctem/server/pkg/domain/attribution"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/filterspec"
	"github.com/openctemio/openctem/server/pkg/pagination"
)

type listSeed struct {
	tenant shared.ID
	ids    map[string]string // key -> asset id
}

func seedAssetList(ctx context.Context, t *testing.T, db *sql.DB) listSeed {
	t.Helper()
	s := listSeed{tenant: seedTestTenant(ctx, t, db), ids: map[string]string{}}
	tid := s.tenant.String()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	type row struct {
		key, name, typ, crit, exposure, env, provider, class string
		tags                                                 []string
		risk                                                 int
		crown                                                bool
		desc                                                 string
		lastSeenAgo                                          time.Duration
		props                                                string
	}
	rows := []row{
		{"d1", "example.com", "domain", "high", "public", "production", "", "public", []string{"prod"}, 80, true, "", 24 * time.Hour, `{}`},
		{"s1", "api.example.com", "subdomain", "medium", "public", "staging", "aws", "internal", []string{"prod", "web"}, 30, false, "payments gateway", time.Hour, `{"aliases":["pay-gw"]}`},
		{"s2", "evilexample.com", "subdomain", "low", "private", "", "unset_like", "", nil, 5, false, "", 48 * time.Hour, `{}`},
		{"ip1", "10.1.2.3", "ip_address", "critical", "public", "", "", "", []string{"edge"}, 95, false, "", 2 * time.Hour, `{"asn":"64500"}`},
		{"ip2", "192.168.1.5", "ip_address", "low", "isolated", "", "", "", nil, 0, false, "", 72 * time.Hour, `{}`},
		{"h1", "10.1.2.9", "host", "medium", "private", "development", "", "", nil, 10, false, "", 3 * time.Hour, `{}`},
		{"c1", "cert-one", "certificate", "low", "public", "", "", "", nil, 1, false, "", 5 * time.Hour, `{"not_after":"2026-12-01T00:00:00Z"}`},
	}
	for i, r := range rows {
		id := shared.NewID().String()
		s.ids[r.key] = id
		var env, provider, class any
		if r.env != "" {
			env = r.env
		}
		if r.provider != "" {
			provider = r.provider
		}
		if r.class != "" {
			class = r.class
		}
		created := time.Now().Add(-time.Duration(i+1) * 24 * time.Hour)
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, scope, exposure, environment, provider,
			data_classification, tags, risk_score, is_crown_jewel, description, last_seen, first_seen, created_at, properties)
			VALUES ($1,$2,$3,$4,$5,'active','external',$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15,$16::jsonb)`,
			id, tid, r.name, r.typ, r.crit, r.exposure, env, provider, class, pqStrings(r.tags), r.risk, r.crown, r.desc,
			time.Now().Add(-r.lastSeenAgo), created, r.props)
	}
	now := time.Now()
	exec(`INSERT INTO asset_technologies (tenant_id, asset_id, name_key, name, version, category, first_seen, last_seen)
		VALUES ($1,$2,'nginx','nginx','1.25.3','web_server',$3,$3), ($1,$4,'react','React','','js_library',$3,$3)`,
		tid, s.ids["s1"], now, s.ids["d1"])
	exec(`INSERT INTO asset_liveness (tenant_id, asset_id, state) VALUES ($1,$2,'alive'), ($1,$3,'gone')`, tid, s.ids["s1"], s.ids["ip2"])
	exec(`INSERT INTO asset_resolution (tenant_id, asset_id, state, checked_at) VALUES ($1,$2,'not_resolving',now())`, tid, s.ids["s2"])
	exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1,$2,'needs_review',40), ($3,$2,'discovered',70)`,
		s.ids["s2"], tid, s.ids["s1"])
	exec(`INSERT INTO easm_evidence (id, tenant_id, asset_id, rule, technique, source, weight)
		VALUES ($1,$2,$3,'tenant_scanned','cert_transparency','scope_target:'||$4,1)`, shared.NewID().String(), tid, s.ids["s1"], shared.NewID().String())
	bu := shared.NewID().String()
	exec(`INSERT INTO business_units (id, tenant_id, name) VALUES ($1,$2,'payments')`, bu, tid)
	exec(`INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES ($1,$2,$3,$4)`, shared.NewID().String(), tid, bu, s.ids["s1"])
	s.ids["bu"] = bu
	exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type, is_control_plane)
		VALUES ($1,$2,$3,'depends_on',true)`, tid, s.ids["s1"], s.ids["d1"])
	return s
}

func pqStrings(v []string) any {
	if v == nil {
		v = []string{}
	}
	return "{" + strings.Join(v, ",") + "}"
}

func assetIDsSorted(as []*asset.Asset) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.ID().String())
	}
	sort.Strings(out)
	return out
}

// Every old param of GET /assets selects, through the registry, exactly the
// assets the old Filter selected.
func TestAssetListWhere_LegacyParity(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewAssetRepository(&DB{DB: db})
	s := seedAssetList(ctx, t, db)
	other := seedAssetList(ctx, t, db) // a second tenant with the same assets
	tid := s.tenant.String()
	ptr := func(v bool) *bool { return &v }
	iptr := func(v int) *int { return &v }
	tptr := func(v time.Time) *time.Time { return &v }
	str := func(v string) *string { return &v }
	day := time.Now().Add(-30 * time.Hour).UTC().Truncate(time.Second)
	approved, _, _ := attribution.ParseFilter([]string{"approved"})
	unconfirmed, _, _ := attribution.ParseFilter([]string{"unconfirmed"})
	cases := []struct {
		params string
		old    asset.Filter
	}{
		{"types=subdomain,domain", asset.Filter{Types: []asset.AssetType{"subdomain", "domain"}}},
		{"criticalities=high,critical", asset.Filter{Criticalities: []asset.Criticality{"high", "critical"}}},
		{"exposures=public", asset.Filter{Exposures: []asset.Exposure{"public"}}},
		{"tags=prod", asset.Filter{Tags: []string{"prod"}}},
		{"tags=prod,web&tags_mode=all", asset.Filter{Tags: []string{"prod", "web"}, TagsMatchAll: true}},
		{"exclude_tags=prod", asset.Filter{ExcludeTags: []string{"prod"}}},
		{"search=pay", asset.Filter{Search: str("pay")}},
		{"search=api", asset.Filter{Search: str("api")}},
		{"min_risk_score=30&max_risk_score=90", asset.Filter{MinRiskScore: iptr(30), MaxRiskScore: iptr(90)}},
		{"is_crown_jewel=true", asset.Filter{IsCrownJewel: ptr(true)}},
		{"environments=production,staging", asset.Filter{Environments: []string{"production", "staging"}}},
		{"providers=aws", asset.Filter{Providers: []asset.Provider{"aws"}}},
		{"providers=unset", asset.Filter{Providers: []asset.Provider{"unset"}}},
		{"data_classifications=public", asset.Filter{DataClassifications: []string{"public"}}},
		{"technology=nginx", asset.Filter{Technologies: []string{"nginx"}}},
		{"technology=nginx&technology_version=1.25.3", asset.Filter{Technologies: []string{"nginx"}, TechnologyVersion: str("1.25.3")}},
		{"technology=nginx&technology_version=9", asset.Filter{Technologies: []string{"nginx"}, TechnologyVersion: str("9")}},
		{"technology_category=js_library", asset.Filter{TechnologyCategories: []string{"js_library"}}},
		{"under=example.com", asset.Filter{UnderDomains: []string{"example.com"}}},
		{"in_cidr=10.1.0.0/16", asset.Filter{InCIDRs: []string{"10.1.0.0/16"}}},
		{"in_cidr=10.1.2.3/32", asset.Filter{InCIDRs: []string{"10.1.2.3/32"}}},
		{"liveness=alive,unknown", asset.Filter{LivenessStates: []string{"alive", "unknown"}}},
		{"resolution=not_resolving", asset.Filter{Resolution: "not_resolving"}},
		{"attribution=approved", asset.Filter{Attribution: &approved}},
		{"attribution=unconfirmed", asset.Filter{Attribution: &unconfirmed}},
		{"min_confidence=50", asset.Filter{MinConfidence: iptr(50)}},
		{"discovered_by=tenant_scanned", asset.Filter{DiscoveredBy: []string{"tenant_scanned"}}},
		{"discovery_technique=cert_transparency", asset.Filter{DiscoveryTechniques: []string{"cert_transparency"}}},
		{"business_unit_ids=" + s.ids["bu"], asset.Filter{BusinessUnitIDs: []string{s.ids["bu"]}}},
		{"is_control_plane=true", asset.Filter{IsControlPlane: ptr(true)}},
		{"is_control_plane=false", asset.Filter{IsControlPlane: ptr(false)}},
		{"has_owner=false", asset.Filter{HasOwner: ptr(false)}},
		{"has_findings=false", asset.Filter{HasFindings: ptr(false)}},
		{"internet_facing=true", asset.Filter{InternetFacing: ptr(true)}},
		{"last_seen_after=" + day.Format(time.RFC3339), asset.Filter{LastSeenAfter: tptr(day)}},
		{"last_seen_before=" + day.Format(time.RFC3339), asset.Filter{LastSeenBefore: tptr(day)}},
		{"first_seen_before=" + day.Format(time.RFC3339), asset.Filter{CreatedBefore: tptr(day)}},
		{"expires_before=2027-01-01", asset.Filter{ExpiresBefore: tptr(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))}},
		{"ids=" + s.ids["d1"] + "," + s.ids["ip1"], asset.Filter{IDs: []string{s.ids["d1"], s.ids["ip1"]}}},
		{"scope_status=not_covered,internal", asset.Filter{ScopeStatuses: []string{"not_covered", "internal"}}},
		{"monitoring_state=monitored", asset.Filter{MonitoringStates: []string{"monitored"}}},
		{"freshness=never", asset.Filter{Freshness: "never"}},
		{"coverage=uncovered", asset.Filter{Coverage: "uncovered"}},
		{"program_assets=exclude", asset.Filter{ProgramAssets: "exclude"}},
		{"primary=true", asset.Filter{Primary: true}},
		{"sub_type=x", asset.Filter{SubType: str("x")}},
	}
	for _, c := range cases {
		t.Run(c.params, func(t *testing.T) {
			old := c.old
			old.TenantID = &tid
			oldRes, err := repo.List(ctx, old, asset.NewListOptions(), paginationAll())
			if err != nil {
				t.Fatalf("old: %v", err)
			}
			q, _ := url.ParseQuery(c.params)
			if q.Has("tags_mode") && q.Get("tags_mode") == "all" {
				q["tag_all"] = q["tags"]
				q.Del("tags")
				q.Del("tags_mode")
			}
			if q.Has("technology_version") {
				q.Set("technology", q.Get("technology")+"@"+q.Get("technology_version"))
				q.Del("technology_version")
			}
			q.Set("per_page", "100")
			spec, err := filterspec.ParseValues(q, assetlist.Fields, filterspec.Options{Unknown: filterspec.UnknownStrict})
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			w, err := filterspec.Compile(spec, assetlist.Fields, filterspec.SystemActor(s.tenant, "parity test"))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			newRes, err := repo.ListWhere(ctx, asset.WhereQuery{Where: w, PerPage: 100})
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			got, want := assetIDsSorted(newRes.Data), assetIDsSorted(oldRes.Data)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("ids differ\nold %v\nnew %v", want, got)
			}
			if newRes.Total != oldRes.Total {
				t.Fatalf("total old %d new %d", oldRes.Total, newRes.Total)
			}
			for _, id := range got {
				for _, oid := range other.ids {
					if id == oid {
						t.Fatal("another tenant's asset matched")
					}
				}
			}
		})
	}
}

// Every field and operator of the registry compiles and runs, as the list
// (alias a) and as the search box reads it (bare table name).
func TestAssetListWhere_EveryFieldRuns(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewAssetRepository(&DB{DB: db})
	s := seedAssetList(ctx, t, db)
	user := shared.NewID()
	actor, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: s.tenant, UserID: user,
		Scope: &shared.DataScope{TenantID: s.tenant, UserID: user}})
	if err != nil {
		t.Fatal(err)
	}
	samples := map[string]string{
		"name": "api-*", "technology": "nginx@1.25.3", "under": "example.com", "domain": "example.com",
		"sub_type": "x", "tag": "prod", "tag_all": "prod", "provider": "aws", "discovery_source": "x",
		"technology_version": "1", "discovery_technique": "x", "sync_status": "synced",
	}
	bare := assetlist.Fields.Rebase("a", "assets")
	for _, f := range assetlist.Fields.Fields() {
		for _, op := range f.Ops {
			var v any
			switch f.Type {
			case filterspec.TypeEnum:
				v = f.Enum[0]
			case filterspec.TypeID:
				v = shared.NewID().String()
			case filterspec.TypeInt:
				v = 1
			case filterspec.TypeTime:
				v = "2026-01-01T00:00:00Z"
			case filterspec.TypeBool:
				v = true
			case filterspec.TypeInet:
				v = "10.0.0.0/8"
			default:
				v = samples[f.Name]
				if v == "" {
					v = "x"
				}
			}
			if op == filterspec.OpIn || op == filterspec.OpNotIn {
				v = []any{v}
			}
			if op == filterspec.OpIsNull {
				v = true
			}
			doc := map[string]any{"filter": map[string]any{"field": f.Name, "op": string(op), "value": v}}
			spec, err := filterspec.ParseDocumentValue(doc, assetlist.Fields, filterspec.Options{})
			if err != nil {
				t.Errorf("%s %s: parse: %v", f.Name, op, err)
				continue
			}
			w, err := filterspec.Compile(spec, assetlist.Fields, actor)
			if err != nil {
				t.Errorf("%s %s: compile: %v", f.Name, op, err)
				continue
			}
			if _, err := repo.ListWhere(ctx, asset.WhereQuery{Where: w, PerPage: 5}); err != nil {
				t.Errorf("%s %s: list: %v", f.Name, op, err)
			}
			wb, err := filterspec.Compile(spec, bare, actor)
			if err != nil {
				t.Errorf("%s %s: compile bare: %v", f.Name, op, err)
				continue
			}
			var n int
			//nolint:gosec // G202: compiled from registry constants
			if err := db.QueryRowContext(ctx, "SELECT count(*) FROM assets WHERE "+wb.SQL, wb.Args...).Scan(&n); err != nil {
				t.Errorf("%s %s: bare: %v", f.Name, op, err)
			}
		}
	}
}

// A scoped member sees only their scope rows; an OR across fields never
// reaches outside it; another tenant's assets never match; keyset pages
// walk every row once.
func TestAssetListWhere_ScopeTenantAndKeyset(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewAssetRepository(&DB{DB: db})
	s := seedAssetList(ctx, t, db)
	other := seedAssetList(ctx, t, db)
	user := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'u')`, user.String(), user.String()+"@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1,$2,$3)`,
		user.String(), s.tenant.String(), s.ids["s1"]); err != nil {
		t.Skipf("user_accessible_assets is not writable here: %v", err)
	}
	actor, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: s.tenant, UserID: user,
		Scope: &shared.DataScope{TenantID: s.tenant, UserID: user}})
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{"filter": map[string]any{"any": []any{
		map[string]any{"field": "type", "op": "in", "value": []any{"domain", "ip_address"}},
		map[string]any{"field": "tag", "op": "in", "value": []any{"web"}},
		map[string]any{"field": "id", "op": "in", "value": []any{other.ids["s1"], other.ids["d1"]}},
	}}}
	spec, err := filterspec.ParseDocumentValue(doc, assetlist.Fields, filterspec.Options{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := filterspec.Compile(spec, assetlist.Fields, actor)
	if err != nil {
		t.Fatal(err)
	}
	res, err := repo.ListWhere(ctx, asset.WhereQuery{Where: w, PerPage: 50})
	if err != nil {
		t.Fatal(err)
	}
	if got := assetIDsSorted(res.Data); len(got) != 1 || got[0] != s.ids["s1"] || res.Total != 1 {
		t.Fatalf("scoped member saw %v (total %d), want only s1", got, res.Total)
	}

	// Keyset: an unrestricted caller walks the tenant two rows at a time.
	sys := filterspec.SystemActor(s.tenant, "keyset test")
	w, err = filterspec.Compile(&filterspec.Spec{}, assetlist.Fields, sys)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var after *asset.Cursor
	for range 10 {
		page, err := repo.ListWhere(ctx, asset.WhereQuery{Where: w, PerPage: 2, Keyset: true, After: after})
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range page.Data {
			if seen[a.ID().String()] {
				t.Fatalf("keyset repeated %s", a.ID())
			}
			seen[a.ID().String()] = true
		}
		if page.NextCursor == "" {
			break
		}
		c, err := asset.DecodeCursor(page.NextCursor)
		if err != nil {
			t.Fatal(err)
		}
		after = &c
	}
	if len(seen) != len(s.ids)-1 { // ids holds the business unit too
		t.Fatalf("keyset saw %d assets, want %d", len(seen), len(s.ids)-1)
	}
}

func paginationAll() pagination.Pagination { return pagination.New(1, 100) }

// Above asset.CountCap the total stops at the cap and says so.
func TestAssetListWhere_CountCap(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewAssetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, scope, exposure)
		SELECT uuid_generate_v7(), $1, 'cap-' || g || '.example.com', 'subdomain', 'low', 'active', 'external', 'public'
		FROM generate_series(1, $2) g`, tenant.String(), asset.CountCap+5); err != nil {
		t.Fatal(err)
	}
	w, err := filterspec.Compile(&filterspec.Spec{}, assetlist.Fields, filterspec.SystemActor(tenant, "count cap test"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := repo.ListWhere(ctx, asset.WhereQuery{Where: w, PerPage: 10})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Capped || res.Total != asset.CountCap || len(res.Data) != 10 {
		t.Fatalf("capped=%v total=%d rows=%d", res.Capped, res.Total, len(res.Data))
	}
}
