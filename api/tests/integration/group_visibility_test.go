package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	businessunitdom "github.com/openctemio/openctem/api/pkg/domain/businessunit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Group visibility follows the data scope (research/233 D4, section 6.1
// fixture on today's tables). Asset groups, business units and business
// services used to be listed tenant-wide with their names, descriptions and
// owners; a restricted reader now sees one only when it holds an asset in
// their scope (a unit also when a unit below it does), or, for an asset
// group, when a scope rule of their team names it. Anything else is absent
// from lists, totals and search and answers 404 by id.
//
// Fixture, tenant T1 (T2 has one group, unit and service of its own):
//
//	units:    Company > Retail > {Checkout {x,y}, Catalog {y,z}}; Company > Corporate IT {w}
//	groups:   Checkout {x,y}, Catalog {y,z}, Corporate IT {w}, PCI scope {x,w},
//	          Onboarding {} (named by ck's scope rule), Fresh {} (named by nobody)
//	services: Checkout {x,y}, Catalog {y,z}, Corporate IT {w}, PCI scope {x,w}
//
// Readers: admin (full data), ck (scope rule on Checkout and Onboarding →
// {x,y}), xo (direct grant on x), it (scope rule on Corporate IT → {w}),
// none (a member with no scope), t2 (a member of T2).

type visFixture struct {
	db         *sql.DB
	t1, t2     shared.ID
	readers    map[string]datascope.Caller
	groups     map[string]shared.ID
	units      map[string]shared.ID
	services   map[string]shared.ID
	t2Group    shared.ID
	t2Unit     shared.ID
	t2Service  shared.ID
	groupSvc   *assetapp.AssetGroupService
	unitSvc    *assetapp.BusinessUnitService
	serviceH   *handler.BusinessServiceHandler
	enf        *datascope.Enforcer
	ownerEmail string
}

func newVisFixture(t *testing.T) *visFixture {
	t.Helper()
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	f := &visFixture{
		db: db, t1: createTestTenant(t, db, "vis233-t1"), t2: createTestTenant(t, db, "vis233-t2"),
		readers: map[string]datascope.Caller{}, groups: map[string]shared.ID{},
		units: map[string]shared.ID{}, services: map[string]shared.ID{},
		ownerEmail: "owner@vis233.test",
	}
	t.Cleanup(func() {
		for _, tn := range []shared.ID{f.t1, f.t2} {
			for _, q := range []string{
				`DELETE FROM user_accessible_assets WHERE tenant_id = $1`,
				`DELETE FROM group_asset_scope_rules WHERE tenant_id = $1`,
				`DELETE FROM group_members WHERE group_id IN (SELECT id FROM groups WHERE tenant_id = $1)`,
				`DELETE FROM groups WHERE tenant_id = $1`,
				`DELETE FROM business_service_assets WHERE tenant_id = $1`,
				`DELETE FROM business_services WHERE tenant_id = $1`,
				`DELETE FROM business_unit_assets WHERE tenant_id = $1`,
				`DELETE FROM business_units WHERE tenant_id = $1`,
				`DELETE FROM asset_group_members WHERE asset_group_id IN (SELECT id FROM asset_groups WHERE tenant_id = $1)`,
				`DELETE FROM asset_groups WHERE tenant_id = $1`,
				`DELETE FROM findings WHERE tenant_id = $1`,
				`DELETE FROM assets WHERE tenant_id = $1`,
				`DELETE FROM tenants WHERE id = $1`,
			} {
				_, _ = db.ExecContext(ctx, q, tn.String())
			}
		}
	})

	asset := func(tenant shared.ID, name string) shared.ID {
		id := seedActAsset(t, db, tenant, name+".vis233.test")
		exec(`INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1, $2, 'sast', 'test', 'm', 'high', $3, 'new')`, tenant.String(), id.String(), shared.NewID().String())
		return id
	}
	x, y, z, w := asset(f.t1, "x"), asset(f.t1, "y"), asset(f.t1, "z"), asset(f.t1, "w")
	t2a := asset(f.t2, "t2a")

	group := func(tenant shared.ID, name string, members ...shared.ID) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO asset_groups (id, tenant_id, name, description, owner, owner_email)
			VALUES ($1, $2, $3, $4, 'Owner Name', $5)`, id.String(), tenant.String(), name, "about "+name, f.ownerEmail)
		for _, m := range members {
			exec(`INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2)`, id.String(), m.String())
		}
		return id
	}
	f.groups["Checkout"] = group(f.t1, "Checkout", x, y)
	f.groups["Catalog"] = group(f.t1, "Catalog", y, z)
	f.groups["Corporate IT"] = group(f.t1, "Corporate IT", w)
	f.groups["PCI scope"] = group(f.t1, "PCI scope", x, w)
	f.groups["Onboarding"] = group(f.t1, "Onboarding")
	f.groups["Fresh"] = group(f.t1, "Fresh")
	f.t2Group = group(f.t2, "T2 group", t2a)

	unit := func(tenant shared.ID, name string, parent *shared.ID, members ...shared.ID) shared.ID {
		id := shared.NewID()
		var p any
		if parent != nil {
			p = parent.String()
		}
		exec(`INSERT INTO business_units (id, tenant_id, name, owner_name, owner_email, parent_id)
			VALUES ($1, $2, $3, 'Owner Name', $4, $5)`, id.String(), tenant.String(), name, f.ownerEmail, p)
		for _, m := range members {
			exec(`INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES ($1, $2, $3, $4)`,
				shared.NewID().String(), tenant.String(), id.String(), m.String())
		}
		return id
	}
	company := unit(f.t1, "Company", nil)
	retail := unit(f.t1, "Retail", &company)
	f.units["Company"], f.units["Retail"] = company, retail
	f.units["Checkout"] = unit(f.t1, "Checkout", &retail, x, y)
	f.units["Catalog"] = unit(f.t1, "Catalog", &retail, y, z)
	f.units["Corporate IT"] = unit(f.t1, "Corporate IT", &company, w)
	f.t2Unit = unit(f.t2, "T2 unit", nil, t2a)

	service := func(tenant shared.ID, name string, members ...shared.ID) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO business_services (id, tenant_id, name, owner_name, owner_email)
			VALUES ($1, $2, $3, 'Owner Name', $4)`, id.String(), tenant.String(), name, f.ownerEmail)
		for _, m := range members {
			exec(`INSERT INTO business_service_assets (tenant_id, service_id, asset_id) VALUES ($1, $2, $3)`,
				tenant.String(), id.String(), m.String())
		}
		return id
	}
	f.services["Checkout"] = service(f.t1, "Checkout", x, y)
	f.services["Catalog"] = service(f.t1, "Catalog", y, z)
	f.services["Corporate IT"] = service(f.t1, "Corporate IT", w)
	f.services["PCI scope"] = service(f.t1, "PCI scope", x, w)
	f.t2Service = service(f.t2, "T2 service", t2a)

	user := func(name string, tenant shared.ID, assets ...shared.ID) shared.ID {
		id := seedActUser(t, db)
		for _, a := range assets {
			exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
				id.String(), tenant.String(), a.String())
		}
		f.readers[name] = datascope.Caller{UserID: id.String()}
		return id
	}
	admin := user("admin", f.t1)
	f.readers["admin"] = datascope.Caller{UserID: admin.String(), IsAdmin: true}
	ck := user("ck", f.t1, x, y)
	user("xo", f.t1, x)
	it := user("it", f.t1, w)
	user("none", f.t1)
	user("t2", f.t2, t2a)

	// The scope rules that grant ck and it their assets; ck's also names the
	// empty Onboarding group.
	team := func(member shared.ID, groupIDs ...shared.ID) {
		gid := shared.NewID()
		exec(`INSERT INTO groups (id, tenant_id, name, slug, is_active) VALUES ($1, $2, $3, $3, TRUE)`,
			gid.String(), f.t1.String(), "team-"+gid.String()[24:])
		exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, gid.String(), member.String())
		ids := make([]string, len(groupIDs))
		for i, g := range groupIDs {
			ids[i] = g.String()
		}
		exec(`INSERT INTO group_asset_scope_rules (id, tenant_id, group_id, name, rule_type, match_asset_group_ids)
			VALUES ($1, $2, $3, 'rule', 'asset_group_match', $4::uuid[])`,
			shared.NewID().String(), f.t1.String(), gid.String(), "{"+strings.Join(ids, ",")+"}")
	}
	team(ck, f.groups["Checkout"], f.groups["Onboarding"])
	team(it, f.groups["Corporate IT"])

	pg := &postgres.DB{DB: db}
	enf := datascope.New(postgres.NewDataScopeRepository(pg), func(ctx context.Context) datascope.Caller {
		c, _ := ctx.Value(actCallerKey{}).(datascope.Caller)
		return c
	}, logger.NewNop())
	f.groupSvc = assetapp.NewAssetGroupService(postgres.NewAssetGroupRepository(pg), logger.NewNop())
	f.groupSvc.SetDataScope(enf)
	f.unitSvc = assetapp.NewBusinessUnitService(postgres.NewBusinessUnitRepository(pg), postgres.NewAssetRepository(pg), logger.NewNop())
	f.unitSvc.SetDataScope(enf)
	f.serviceH = handler.NewBusinessServiceHandler(db, logger.NewNop()).WithDataScope(enf)
	f.enf = enf
	return f
}

// as returns the context of reader name and the tenant they belong to.
func (f *visFixture) as(name string) (context.Context, shared.ID) {
	tenant := f.t1
	if name == "t2" {
		tenant = f.t2
	}
	return asCaller(context.Background(), f.readers[name]), tenant
}

// The section 6 matrix on today's flat groups.
var visGroupMatrix = map[string][]string{
	"admin": {"Catalog", "Checkout", "Corporate IT", "Fresh", "Onboarding", "PCI scope"},
	"ck":    {"Catalog", "Checkout", "Onboarding", "PCI scope"},
	"xo":    {"Checkout", "PCI scope"},
	"it":    {"Corporate IT", "PCI scope"},
	"none":  {},
	"t2":    {"T2 group"},
}

// Business units: the ancestors of a visible unit are visible.
var visUnitMatrix = map[string][]string{
	"admin": {"Catalog", "Checkout", "Company", "Corporate IT", "Retail"},
	"ck":    {"Catalog", "Checkout", "Company", "Retail"},
	"xo":    {"Checkout", "Company", "Retail"},
	"it":    {"Company", "Corporate IT"},
	"none":  {},
	"t2":    {"T2 unit"},
}

var visServiceMatrix = map[string][]string{
	"admin": {"Catalog", "Checkout", "Corporate IT", "PCI scope"},
	"ck":    {"Catalog", "Checkout", "PCI scope"},
	"xo":    {"Checkout", "PCI scope"},
	"it":    {"Corporate IT", "PCI scope"},
	"none":  {},
	"t2":    {"T2 service"},
}

func TestVisibility_AssetGroups_ListGetSearch(t *testing.T) {
	f := newVisFixture(t)
	for reader, want := range visGroupMatrix {
		t.Run(reader, func(t *testing.T) {
			ctx, tenant := f.as(reader)
			out, err := f.groupSvc.ListAssetGroups(ctx, assetapp.ListAssetGroupsInput{TenantID: tenant.String(), Page: 1, PerPage: 50})
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, g := range out.Groups {
				names = append(names, g.Name())
				if wantEmail := reader == "admin"; (g.OwnerEmail() != "") != wantEmail {
					t.Errorf("group %s owner email %q for %s (shown only with full data)", g.Name(), g.OwnerEmail(), reader)
				}
			}
			assertNames(t, "groups", names, want)
			if out.Total != int64(len(want)) {
				t.Errorf("total = %d, want %d (the total counts only visible groups)", out.Total, len(want))
			}

			// Search follows the same rule.
			found, err := f.groupSvc.ListAssetGroups(ctx, assetapp.ListAssetGroupsInput{TenantID: tenant.String(), Search: "Corporate", Page: 1, PerPage: 50})
			if err != nil {
				t.Fatal(err)
			}
			if wantHit := slices.Contains(want, "Corporate IT"); (found.Total == 1) != wantHit || int64(len(found.Groups)) != found.Total {
				t.Errorf("search Corporate: total %d, %d rows; visible=%v", found.Total, len(found.Groups), wantHit)
			}

			// Stats count the visible groups only.
			st, err := f.groupSvc.GetAssetGroupStats(ctx, tenant.String())
			if err != nil {
				t.Fatal(err)
			}
			var byEnv, byCrit int64
			for _, n := range st.ByEnvironment {
				byEnv += n
			}
			for _, n := range st.ByCriticality {
				byCrit += n
			}
			if st.Total != int64(len(want)) || byEnv != st.Total || byCrit != st.Total {
				t.Errorf("stats total %d, by environment %d, by criticality %d; want %d", st.Total, byEnv, byCrit, len(want))
			}

			// By id: visible → the group; anything else (incl. another
			// tenant's) → 404 on the group, its members and its findings.
			ids := map[string]shared.ID{"T2 group": f.t2Group}
			for name, id := range f.groups {
				ids[name] = id
			}
			for name, id := range ids {
				visible := slices.Contains(want, name)
				g, err := f.groupSvc.GetAssetGroup(ctx, tenant.String(), id)
				assertVisible(t, "get group "+name, visible, err)
				if visible && g.Name() != name {
					t.Errorf("get group %s returned %s", name, g.Name())
				}
				_, err = f.groupSvc.GetGroupAssets(ctx, tenant.String(), id, 1, 20)
				assertVisible(t, "group assets "+name, visible, err)
				_, err = f.groupSvc.GetGroupFindings(ctx, tenant.String(), id, 1, 20)
				assertVisible(t, "group findings "+name, visible, err)
			}
		})
	}
}

func TestVisibility_BusinessUnits_ListGetSearch(t *testing.T) {
	f := newVisFixture(t)
	for reader, want := range visUnitMatrix {
		t.Run(reader, func(t *testing.T) {
			ctx, tenant := f.as(reader)
			res, err := f.unitSvc.List(ctx, tenant.String(), businessunitdom.Filter{}, pagination.New(1, 50))
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, u := range res.Data {
				names = append(names, u.Name())
				if wantEmail := reader == "admin"; (u.OwnerEmail() != "") != wantEmail {
					t.Errorf("unit %s owner email %q for %s", u.Name(), u.OwnerEmail(), reader)
				}
			}
			assertNames(t, "units", names, want)
			if res.Total != int64(len(want)) {
				t.Errorf("total = %d, want %d", res.Total, len(want))
			}
			search := "Corporate"
			found, err := f.unitSvc.List(ctx, tenant.String(), businessunitdom.Filter{Search: &search}, pagination.New(1, 50))
			if err != nil {
				t.Fatal(err)
			}
			if wantHit := slices.Contains(want, "Corporate IT"); (found.Total == 1) != wantHit {
				t.Errorf("search Corporate: total %d, visible=%v", found.Total, wantHit)
			}

			ids := map[string]shared.ID{"T2 unit": f.t2Unit}
			for name, id := range f.units {
				ids[name] = id
			}
			for name, id := range ids {
				visible := slices.Contains(want, name)
				_, err := f.unitSvc.Get(ctx, tenant.String(), id.String())
				assertVisible(t, "get unit "+name, visible, err)
			}
		})
	}
}

func TestVisibility_BusinessServices_ListGet(t *testing.T) {
	f := newVisFixture(t)
	for reader, want := range visServiceMatrix {
		t.Run(reader, func(t *testing.T) {
			ctx, tenant := f.as(reader)
			rec := f.serve(ctx, tenant, http.MethodGet, "/", "", f.serviceH.List)
			if rec.Code != http.StatusOK {
				t.Fatalf("list: %d %s", rec.Code, rec.Body)
			}
			var page struct {
				Data  []handler.BusinessServiceResponse `json:"data"`
				Total int64                             `json:"total"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, s := range page.Data {
				names = append(names, s.Name)
				if wantEmail := reader == "admin"; (s.OwnerEmail != "") != wantEmail {
					t.Errorf("service %s owner email %q for %s", s.Name, s.OwnerEmail, reader)
				}
			}
			assertNames(t, "services", names, want)
			if page.Total != int64(len(want)) {
				t.Errorf("total = %d, want %d (was a tenant-wide COUNT)", page.Total, len(want))
			}

			ids := map[string]shared.ID{"T2 service": f.t2Service}
			for name, id := range f.services {
				ids[name] = id
			}
			for name, id := range ids {
				wantCode := http.StatusNotFound
				if slices.Contains(want, name) {
					wantCode = http.StatusOK
				}
				if rec := f.serve(ctx, tenant, http.MethodGet, "/"+id.String(), "", f.serviceH.Get); rec.Code != wantCode {
					t.Errorf("get service %s: %d, want %d", name, rec.Code, wantCode)
				}
				if rec := f.serve(ctx, tenant, http.MethodGet, "/"+id.String()+"/assets", "", f.serviceH.ListAssets); rec.Code != wantCode {
					t.Errorf("service %s assets: %d, want %d", name, rec.Code, wantCode)
				}
			}
		})
	}
}

// A write to a container the caller cannot see answers 404 like a read; an
// empty one (just created) stays writable, and a restricted caller's edit
// keeps the owner email they are never shown.
func TestVisibility_WritesFollowVisibility(t *testing.T) {
	f := newVisFixture(t)
	ctx, tenant := f.as("ck")
	name := "renamed"

	_, err := f.groupSvc.UpdateAssetGroup(ctx, tenant.String(), f.groups["Corporate IT"], assetapp.UpdateAssetGroupInput{Name: &name})
	assertVisible(t, "ck updates Corporate IT group", false, err)
	if err := f.groupSvc.DeleteAssetGroup(ctx, tenant.String(), f.groups["Corporate IT"]); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("ck deletes Corporate IT group: %v, want not found", err)
	}
	if _, err := f.groupSvc.UpdateAssetGroup(ctx, tenant.String(), f.groups["Fresh"], assetapp.UpdateAssetGroupInput{Name: &name}); err != nil {
		t.Errorf("ck updates the empty Fresh group: %v", err)
	}
	empty := ""
	desc := "edited"
	if _, err := f.groupSvc.UpdateAssetGroup(ctx, tenant.String(), f.groups["Checkout"], assetapp.UpdateAssetGroupInput{Description: &desc, OwnerEmail: &empty}); err != nil {
		t.Fatalf("ck updates Checkout: %v", err)
	}
	var email string
	if err := f.db.QueryRow(`SELECT owner_email FROM asset_groups WHERE id = $1`, f.groups["Checkout"].String()).Scan(&email); err != nil || email != f.ownerEmail {
		t.Errorf("owner email after ck's edit = %q (%v), want kept %q", email, err, f.ownerEmail)
	}

	if _, err := f.unitSvc.Update(ctx, assetapp.UpdateBusinessUnitInput{TenantID: tenant.String(), ID: f.units["Corporate IT"].String(), Name: name}); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("ck updates Corporate IT unit: %v, want not found", err)
	}
	if _, err := f.unitSvc.Update(ctx, assetapp.UpdateBusinessUnitInput{TenantID: tenant.String(), ID: f.units["Checkout"].String(), Name: "Checkout"}); err != nil {
		t.Fatalf("ck updates Checkout unit: %v", err)
	}
	if err := f.db.QueryRow(`SELECT owner_email FROM business_units WHERE id = $1`, f.units["Checkout"].String()).Scan(&email); err != nil || email != f.ownerEmail {
		t.Errorf("unit owner email after ck's edit = %q (%v), want kept", email, err)
	}
	parent := f.units["Corporate IT"].String()
	if _, err := f.unitSvc.Create(ctx, assetapp.CreateBusinessUnitInput{TenantID: tenant.String(), Name: "child", ParentID: &parent}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("ck creates a unit under Corporate IT: %v, want the parent not found", err)
	}

	body := `{"name":"renamed"}`
	if rec := f.serve(ctx, tenant, http.MethodPut, "/"+f.services["Corporate IT"].String(), body, f.serviceH.Update); rec.Code != http.StatusNotFound {
		t.Errorf("ck updates Corporate IT service: %d, want 404 (not 403, which would confirm it exists)", rec.Code)
	}
	if rec := f.serve(ctx, tenant, http.MethodPost, "/"+f.services["Corporate IT"].String()+"/assets", `{"asset_id":"`+firstAsset(t, f, "x")+`"}`, f.serviceH.LinkAsset); rec.Code != http.StatusNotFound {
		t.Errorf("ck links an asset to Corporate IT service: %d, want 404", rec.Code)
	}
	if rec := f.serve(ctx, tenant, http.MethodPut, "/"+f.services["Checkout"].String(), `{"name":"Checkout","owner_email":""}`, f.serviceH.Update); rec.Code != http.StatusOK {
		t.Fatalf("ck updates Checkout service: %d %s", rec.Code, rec.Body)
	}
	if err := f.db.QueryRow(`SELECT owner_email FROM business_services WHERE id = $1`, f.services["Checkout"].String()).Scan(&email); err != nil || email != f.ownerEmail {
		t.Errorf("service owner email after ck's edit = %q (%v), want kept", email, err)
	}
}

// A unit with no asset of its own but units below it that hold assets is
// not an empty unit: its criticality is inherited by those assets, so a
// reader who cannot see it must not rename, re-rate, move or fill it. Retail
// (Checkout and Catalog below it, assets x, y, z) is invisible to it.
func TestVisibility_UnitWithAssetsBelowIsNotWritable(t *testing.T) {
	f := newVisFixture(t)
	ctx, tenant := f.as("it")
	retail := f.units["Retail"].String()
	critical := "critical"
	if _, err := f.unitSvc.Update(ctx, assetapp.UpdateBusinessUnitInput{TenantID: tenant.String(), ID: retail, Name: "Retail", Criticality: &critical}); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("it updates Retail: %v, want not found", err)
	}
	if err := f.unitSvc.AddAsset(ctx, tenant.String(), retail, firstAsset(t, f, "w")); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("it adds w to Retail: %v, want not found", err)
	}
	if err := f.unitSvc.Delete(ctx, tenant.String(), retail); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("it deletes Retail: %v, want not found", err)
	}
	var crit string
	if err := f.db.QueryRow(`SELECT criticality FROM business_units WHERE id = $1`, retail).Scan(&crit); err != nil || crit == critical {
		t.Errorf("Retail criticality after it's edit = %q (%v), want unchanged", crit, err)
	}
	// A unit it just created (no asset, no unit below) stays writable.
	bu, err := f.unitSvc.Create(ctx, assetapp.CreateBusinessUnitInput{TenantID: tenant.String(), Name: "it fresh"})
	if err != nil {
		t.Fatalf("it creates a unit: %v", err)
	}
	if _, err := f.unitSvc.Update(ctx, assetapp.UpdateBusinessUnitInput{TenantID: tenant.String(), ID: bu.ID().String(), Name: "it fresh 2"}); err != nil {
		t.Errorf("it updates the unit it just created: %v", err)
	}
}

// The scoping overview counts only the services and units the reader sees,
// as their lists do, not the organization's totals.
func TestVisibility_ScopingSummaryCountsVisibleOnly(t *testing.T) {
	f := newVisFixture(t)
	repo := postgres.NewScopingSummaryRepository(&postgres.DB{DB: f.db})
	for _, name := range []string{"admin", "xo", "it", "none"} {
		ctx, tenant := f.as(name)
		scope, err := f.enf.Resolve(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		s, err := repo.GetSummary(ctx, tenant, scope)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := s.BusinessServices.Total, len(visServiceMatrix[name]); got != want {
			t.Errorf("%s: business_services.total = %d, want %d", name, got, want)
		}
		if got, want := s.BusinessUnits.Total, len(visUnitMatrix[name]); got != want {
			t.Errorf("%s: business_units.total = %d, want %d", name, got, want)
		}
	}
}

func firstAsset(t *testing.T, f *visFixture, name string) string {
	t.Helper()
	var id string
	if err := f.db.QueryRow(`SELECT id FROM assets WHERE tenant_id = $1 AND name = $2`, f.t1.String(), name+".vis233.test").Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *visFixture) serve(ctx context.Context, tenant shared.ID, method, path, body string, h http.HandlerFunc) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	r.MethodFunc(method, "/", h)
	r.MethodFunc(method, "/{id}", h)
	r.MethodFunc(method, "/{id}/assets", h)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req = req.WithContext(context.WithValue(ctx, middleware.TenantIDKey, tenant.String()))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func assertNames(t *testing.T, what string, got, want []string) {
	t.Helper()
	sort.Strings(got)
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !slices.Equal(got, want) {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

func assertVisible(t *testing.T, what string, visible bool, err error) {
	t.Helper()
	switch {
	case visible && err != nil:
		t.Errorf("%s: %v, want visible", what, err)
	case !visible && !errors.Is(err, shared.ErrNotFound):
		t.Errorf("%s: %v, want not found (404)", what, err)
	}
}
